"""
WAF v2 Rule Evaluation Engine.

Evaluates HTTP requests against WebACL rules. Separate from waf.py (CRUD)
to keep concerns clean. Reads state directly from waf module-level dicts.

Supports: IPSet, RegexPatternSet, ByteMatch, SizeConstraint, GeoMatch,
LabelMatch, RateBasedStatement, ManagedRuleGroupStatement (stubs),
AND/OR/NOT combinators, text transformations, and WAF log writing to S3.
"""

import base64
import html
import ipaddress
import json
import logging
import re
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field

from ministack.core.responses import new_uuid

logger = logging.getLogger("waf-engine")

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class WafResult:
    action: str = "ALLOW"                         # ALLOW | BLOCK | COUNT
    terminating_rule_id: str = ""
    terminating_rule_type: str = ""                # REGULAR | RATE_BASED | MANAGED_RULE_GROUP | GROUP
    non_terminating_rules: list = field(default_factory=list)
    labels: list = field(default_factory=list)
    rate_based_rules: list = field(default_factory=list)
    custom_response_code: int = 0
    inserted_headers: list = field(default_factory=list)
    source_id: str = ""


# ---------------------------------------------------------------------------
# Rate-based counters — sliding window
# ---------------------------------------------------------------------------

_rate_counters: dict = {}  # (rule_name, aggregate_key) -> deque of timestamps


# ---------------------------------------------------------------------------
# Text transformations
# ---------------------------------------------------------------------------

def _apply_transforms(value, transforms):
    if not value:
        return value or ""
    text = value if isinstance(value, str) else str(value)
    for t in (transforms or []):
        ttype = t.get("Type", "NONE").upper()
        if ttype == "LOWERCASE":
            text = text.lower()
        elif ttype == "URL_DECODE":
            text = urllib.parse.unquote(text)
        elif ttype == "HTML_ENTITY_DECODE":
            text = html.unescape(text)
        elif ttype == "COMPRESS_WHITE_SPACE":
            text = re.sub(r"\s+", " ", text)
        # NONE and unknown → identity
    return text


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

def _extract_field(field_to_match, request_info):
    if not field_to_match:
        return ""
    # AWS uses PascalCase in JSON API but Terraform sends snake_case keys
    # Normalise to snake_case for matching
    keys = {k.lower().replace("-", "_"): v for k, v in field_to_match.items()}

    if "uripath" in keys or "uri_path" in keys:
        return request_info.get("uri", "")
    if "querystring" in keys or "query_string" in keys:
        return request_info.get("query_string", "")
    if "body" in keys:
        body = request_info.get("body", "")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return body[:8192]  # AWS truncates at 8KB
    if "method" in keys:
        return request_info.get("method", "")
    if "singleheader" in keys or "single_header" in keys:
        header_spec = keys.get("singleheader") or keys.get("single_header", {})
        header_name = header_spec.get("Name", header_spec.get("name", "")).lower()
        return request_info.get("headers", {}).get(header_name, "")
    if "allheaders" in keys or "headers" in keys:
        hdrs = request_info.get("headers", {})
        return "\n".join(f"{k}: {v}" for k, v in hdrs.items())
    return ""


# ---------------------------------------------------------------------------
# Statement evaluators
# ---------------------------------------------------------------------------

def _get_stmt(stmt, *keys):
    """Look up a statement value trying multiple key variants (PascalCase and snake_case)."""
    for k in keys:
        if k in stmt:
            return stmt[k]
    return None


def _evaluate_statement(stmt, request_info, labels):
    """Evaluate a single WAF statement. Returns (matched: bool, new_labels: list)."""
    if not stmt:
        return False, []

    # --- Combinator statements ---
    inner = _get_stmt(stmt, "AndStatement", "and_statement")
    if inner is not None:
        stmts = inner.get("Statements") or inner.get("statements", [])
        all_labels = []
        for s in stmts:
            matched, sl = _evaluate_statement(s, request_info, labels + all_labels)
            all_labels.extend(sl)
            if not matched:
                return False, []
        return True, all_labels

    inner = _get_stmt(stmt, "OrStatement", "or_statement")
    if inner is not None:
        stmts = inner.get("Statements") or inner.get("statements", [])
        for s in stmts:
            matched, sl = _evaluate_statement(s, request_info, labels)
            if matched:
                return True, sl
        return False, []

    inner = _get_stmt(stmt, "NotStatement", "not_statement")
    if inner is not None:
        sub = inner.get("Statement") or inner.get("statement", {})
        matched, sl = _evaluate_statement(sub, request_info, labels)
        return not matched, sl

    # --- IP Set reference ---
    inner = _get_stmt(stmt, "IPSetReferenceStatement", "ip_set_reference_statement")
    if inner is not None:
        return _eval_ip_set(inner, request_info)

    # --- Regex pattern set reference ---
    inner = _get_stmt(stmt, "RegexPatternSetReferenceStatement", "regex_pattern_set_reference_statement")
    if inner is not None:
        return _eval_regex_pattern_set(inner, request_info)

    # --- Regex match (inline) ---
    inner = _get_stmt(stmt, "RegexMatchStatement", "regex_match_statement")
    if inner is not None:
        return _eval_regex_match(inner, request_info)

    # --- Byte match ---
    inner = _get_stmt(stmt, "ByteMatchStatement", "byte_match_statement")
    if inner is not None:
        return _eval_byte_match(inner, request_info)

    # --- Size constraint ---
    inner = _get_stmt(stmt, "SizeConstraintStatement", "size_constraint_statement")
    if inner is not None:
        return _eval_size_constraint(inner, request_info)

    # --- Label match ---
    inner = _get_stmt(stmt, "LabelMatchStatement", "label_match_statement")
    if inner is not None:
        return _eval_label_match(inner, labels)

    # --- Geo match ---
    inner = _get_stmt(stmt, "GeoMatchStatement", "geo_match_statement")
    if inner is not None:
        return _eval_geo_match(inner, request_info)

    # --- Rate based ---
    inner = _get_stmt(stmt, "RateBasedStatement", "rate_based_statement")
    if inner is not None:
        return _eval_rate_based(inner, request_info, labels)

    # --- Managed rule group (stub) ---
    inner = _get_stmt(stmt, "ManagedRuleGroupStatement", "managed_rule_group_statement")
    if inner is not None:
        return _eval_managed_rule_group(inner, request_info)

    # --- Rule group reference ---
    inner = _get_stmt(stmt, "RuleGroupReferenceStatement", "rule_group_reference_statement")
    if inner is not None:
        return _eval_rule_group_reference(inner, request_info, labels)

    # Unknown statement type — no match
    logger.debug("Unknown WAF statement type: %s", list(stmt.keys()))
    return False, []


def _eval_ip_set(stmt, request_info):
    from ministack.services import waf
    arn = stmt.get("ARN", "")
    # Find IP set by ARN
    ip_set = None
    for s in waf._ip_sets.values():
        if s["ARN"] == arn:
            ip_set = s
            break
    if not ip_set:
        return False, []

    client_ip = request_info.get("client_ip", "127.0.0.1")
    # Handle forwarded header if specified
    ftm = stmt.get("IPSetForwardedIPConfig") or {}
    if ftm.get("HeaderName"):
        hdr_val = request_info.get("headers", {}).get(ftm["HeaderName"].lower(), "")
        if hdr_val:
            pos = ftm.get("Position", "FIRST")
            ips = [ip.strip() for ip in hdr_val.split(",")]
            client_ip = ips[0] if pos == "FIRST" else ips[-1]

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False, []

    for cidr_str in ip_set.get("Addresses", []):
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            if addr in network:
                return True, []
        except ValueError:
            continue
    return False, []


def _eval_regex_pattern_set(stmt, request_info):
    from ministack.services import waf
    arn = stmt.get("ARN", "")
    rps = None
    for s in waf._regex_pattern_sets.values():
        if s["ARN"] == arn:
            rps = s
            break
    if not rps:
        return False, []

    ftm = stmt.get("FieldToMatch", stmt.get("field_to_match", {}))
    transforms = stmt.get("TextTransformations", stmt.get("text_transformations", []))
    value = _apply_transforms(_extract_field(ftm, request_info), transforms)

    for entry in rps.get("RegularExpressionList", []):
        pattern = entry.get("RegexString", "") if isinstance(entry, dict) else str(entry)
        try:
            if re.search(pattern, value):
                return True, []
        except re.error:
            continue
    return False, []


def _eval_regex_match(stmt, request_info):
    ftm = stmt.get("FieldToMatch", stmt.get("field_to_match", {}))
    transforms = stmt.get("TextTransformations", stmt.get("text_transformations", []))
    regex = stmt.get("RegexString", "")
    value = _apply_transforms(_extract_field(ftm, request_info), transforms)
    try:
        return bool(re.search(regex, value)), []
    except re.error:
        return False, []


def _decode_search_string(raw):
    """Decode SearchString which boto3 sends as base64-encoded."""
    if not raw:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    # Try base64 decode (boto3 encodes blob fields as base64)
    try:
        decoded = base64.b64decode(raw)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return str(raw)


def _eval_byte_match(stmt, request_info):
    ftm = stmt.get("FieldToMatch", stmt.get("field_to_match", {}))
    transforms = stmt.get("TextTransformations", stmt.get("text_transformations", []))
    search_string = _decode_search_string(stmt.get("SearchString", ""))
    pos_constraint = stmt.get("PositionalConstraint", "CONTAINS").upper()
    value = _apply_transforms(_extract_field(ftm, request_info), transforms)
    search = _apply_transforms(search_string, transforms)

    if pos_constraint == "EXACTLY":
        return value == search, []
    elif pos_constraint == "STARTS_WITH":
        return value.startswith(search), []
    elif pos_constraint == "ENDS_WITH":
        return value.endswith(search), []
    elif pos_constraint == "CONTAINS":
        return search in value, []
    elif pos_constraint == "CONTAINS_WORD":
        return bool(re.search(r'\b' + re.escape(search) + r'\b', value)), []
    return False, []


def _eval_size_constraint(stmt, request_info):
    ftm = stmt.get("FieldToMatch", stmt.get("field_to_match", {}))
    transforms = stmt.get("TextTransformations", stmt.get("text_transformations", []))
    comparison = stmt.get("ComparisonOperator", "GT").upper()
    size = int(stmt.get("Size", 0))
    value = _apply_transforms(_extract_field(ftm, request_info), transforms)
    actual_size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)

    if comparison == "EQ":
        return actual_size == size, []
    elif comparison == "NE":
        return actual_size != size, []
    elif comparison == "LE":
        return actual_size <= size, []
    elif comparison == "LT":
        return actual_size < size, []
    elif comparison == "GE":
        return actual_size >= size, []
    elif comparison == "GT":
        return actual_size > size, []
    return False, []


def _eval_label_match(stmt, labels):
    scope = stmt.get("Scope", "LABEL").upper()
    key = stmt.get("Key", "")
    if scope == "LABEL":
        return key in labels, []
    elif scope == "NAMESPACE":
        return any(l.startswith(key) for l in labels), []
    return False, []


def _eval_geo_match(stmt, request_info):
    country_codes = stmt.get("CountryCodes", [])
    # Use X-Waf-Country header for simulation, or fallback to request_info country
    country = request_info.get("country", "")
    if not country:
        country = request_info.get("headers", {}).get("x-waf-country", "")
    return country.upper() in [c.upper() for c in country_codes], []


def _eval_rate_based(stmt, request_info, labels):
    limit = int(stmt.get("Limit", 2000))
    window = int(stmt.get("EvaluationWindowSec", 300))
    aggregate_key_type = stmt.get("AggregateKeyType", "IP").upper()

    # Compute aggregate key
    if aggregate_key_type == "IP":
        key = request_info.get("client_ip", "127.0.0.1")
    elif aggregate_key_type == "FORWARDED_IP":
        fwd = request_info.get("headers", {}).get("x-forwarded-for", "")
        key = fwd.split(",")[0].strip() if fwd else request_info.get("client_ip", "127.0.0.1")
    elif aggregate_key_type == "CUSTOM_KEYS":
        # Build key from custom key definitions
        key_parts = []
        for ck in stmt.get("CustomKeys", []):
            if "Header" in ck or "header" in ck:
                hdr_cfg = ck.get("Header") or ck.get("header", {})
                hdr_name = hdr_cfg.get("Name", hdr_cfg.get("name", "")).lower()
                transforms = hdr_cfg.get("TextTransformations", hdr_cfg.get("text_transformations", []))
                hdr_val = request_info.get("headers", {}).get(hdr_name, "")
                key_parts.append(_apply_transforms(hdr_val, transforms))
            elif "QueryString" in ck or "query_string" in ck:
                qs_cfg = ck.get("QueryString") or ck.get("query_string", {})
                transforms = qs_cfg.get("TextTransformations", qs_cfg.get("text_transformations", []))
                key_parts.append(_apply_transforms(request_info.get("query_string", ""), transforms))
            elif "QueryArgument" in ck or "query_argument" in ck:
                qa_cfg = ck.get("QueryArgument") or ck.get("query_argument", {})
                qa_name = qa_cfg.get("Name", qa_cfg.get("name", ""))
                transforms = qa_cfg.get("TextTransformations", qa_cfg.get("text_transformations", []))
                qs = request_info.get("query_string", "")
                qa_val = ""
                for pair in qs.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        if k == qa_name:
                            qa_val = v
                            break
                key_parts.append(_apply_transforms(qa_val, transforms))
            elif "Cookie" in ck or "cookie" in ck:
                c_cfg = ck.get("Cookie") or ck.get("cookie", {})
                c_name = c_cfg.get("Name", c_cfg.get("name", "")).lower()
                transforms = c_cfg.get("TextTransformations", c_cfg.get("text_transformations", []))
                cookie_hdr = request_info.get("headers", {}).get("cookie", "")
                c_val = ""
                for part in cookie_hdr.split(";"):
                    part = part.strip()
                    if "=" in part:
                        ck_name, ck_val = part.split("=", 1)
                        if ck_name.strip().lower() == c_name:
                            c_val = ck_val.strip()
                            break
                key_parts.append(_apply_transforms(c_val, transforms))
            elif "IP" in ck or "ip" in ck:
                key_parts.append(request_info.get("client_ip", "127.0.0.1"))
            elif "ForwardedIP" in ck or "forwarded_ip" in ck:
                fwd = request_info.get("headers", {}).get("x-forwarded-for", "")
                key_parts.append(fwd.split(",")[0].strip() if fwd else request_info.get("client_ip", "127.0.0.1"))
        key = "|".join(key_parts) if key_parts else request_info.get("client_ip", "127.0.0.1")
    elif aggregate_key_type == "CONSTANT":
        key = "CONSTANT"
    else:
        key = request_info.get("client_ip", "127.0.0.1")

    # Check scope-down statement first
    scope_down = stmt.get("ScopeDownStatement")
    if scope_down:
        matched, _ = _evaluate_statement(scope_down, request_info, labels)
        if not matched:
            return False, []

    rule_id = stmt.get("_rule_name", "rate")
    counter_key = (rule_id, key)
    now = time.time()
    counter = _rate_counters.setdefault(counter_key, deque())

    # Clean old entries
    while counter and counter[0] < now - window:
        counter.popleft()
    counter.append(now)

    return len(counter) > limit, []


def _eval_managed_rule_group(stmt, request_info):
    name = stmt.get("Name", "")

    # Use correct label namespace (slug-style, not lowercased group name)
    namespace = _MANAGED_LABEL_NAMESPACE.get(name)
    if namespace is None:
        vendor = stmt.get("VendorName", "AWS")
        namespace = f"awswaf:managed:{vendor.lower()}:{name.lower()}"

    # Check excluded rules
    excluded = {r.get("Name", "") for r in stmt.get("ExcludedRules", [])}

    # Parse rule_action_overrides: {sub_rule_name -> action_dict}
    overrides = {}
    for o in stmt.get("RuleActionOverrides", []):
        overrides[o.get("Name", "")] = o.get("ActionToUse", {})

    new_labels = []
    matched = False

    stubs = _MANAGED_RULE_STUBS.get(name, {})
    for rule_name, check_fn in stubs.items():
        if rule_name in excluded:
            continue
        try:
            if check_fn(request_info):
                label = f"{namespace}:{rule_name}"
                new_labels.append(label)
                # Check if this sub-rule has an override
                override = overrides.get(rule_name)
                if override and ("Count" in override or "count" in override):
                    # Override to COUNT → non-terminating, label emitted but no block
                    pass
                else:
                    # Default action (BLOCK) → terminating
                    matched = True
        except Exception:
            continue

    return matched, new_labels


def _eval_rule_group_reference(stmt, request_info, labels):
    from ministack.services import waf
    arn = stmt.get("ARN", "")
    rg = None
    for g in waf._rule_groups.values():
        if g["ARN"] == arn:
            rg = g
            break
    if not rg:
        return False, []

    excluded = {r.get("Name", "") for r in stmt.get("ExcludedRules", [])}
    all_labels = list(labels)
    matched = False

    rules = sorted(rg.get("Rules", []), key=lambda r: r.get("Priority", 0))
    for rule in rules:
        if rule.get("Name", "") in excluded:
            continue
        rule_stmt = rule.get("Statement", {})
        rule_matched, new_labels = _evaluate_statement(rule_stmt, request_info, all_labels)
        all_labels.extend(new_labels)
        if rule_matched:
            # Apply rule labels
            for rl in rule.get("RuleLabels", []):
                lbl = rl.get("Name", "")
                if lbl:
                    all_labels.append(lbl)
            matched = True

    return matched, [l for l in all_labels if l not in labels]


# ---------------------------------------------------------------------------
# Managed rule group stubs — simple heuristics
# ---------------------------------------------------------------------------

def _has_xss_pattern(text):
    if not text:
        return False
    patterns = [r"<script", r"javascript:", r"on\w+=", r"<iframe", r"<img\s+.*?onerror"]
    return any(re.search(p, str(text), re.IGNORECASE) for p in patterns)


def _has_sqli_pattern(text):
    if not text:
        return False
    patterns = [r"('\s*(OR|AND)\s+)", r"(UNION\s+SELECT)", r"(;\s*DROP\s)", r"(--\s*$)", r"('\s*;\s*)"]
    return any(re.search(p, str(text), re.IGNORECASE) for p in patterns)


def _is_bad_bot(ua):
    if not ua:
        return False
    bad_patterns = [r"(?i)(nmap|sqlmap|nikto|masscan|dirbuster|gobuster|wfuzz)"]
    return any(re.search(p, ua) for p in bad_patterns)


# ---------------------------------------------------------------------------
# Managed rule label namespace map (AWS uses slugs, not lowercased group names)
# ---------------------------------------------------------------------------

_MANAGED_LABEL_NAMESPACE = {
    "AWSManagedRulesCommonRuleSet": "awswaf:managed:aws:core-rule-set",
    "AWSManagedRulesSQLiRuleSet": "awswaf:managed:aws:sql-database",
    "AWSManagedRulesKnownBadInputsRuleSet": "awswaf:managed:aws:known-bad-inputs",
    "AWSManagedRulesLinuxRuleSet": "awswaf:managed:aws:linux-os",
    "AWSManagedRulesAmazonIpReputationList": "awswaf:managed:aws:amazon-ip-list",
}


# ---------------------------------------------------------------------------
# Heuristic helpers for managed sub-rules
# ---------------------------------------------------------------------------

def _has_lfi_pattern(text):
    if not text:
        return False
    return any(p in text for p in ["../", "/etc/passwd", "/proc/self", "/proc/"])


def _has_rfi_pattern(text):
    if not text:
        return False
    return bool(re.search(r"https?://", text, re.IGNORECASE))


def _has_ssrf_pattern(text):
    if not text:
        return False
    return "169.254.169.254" in text


def _has_restricted_ext(text):
    if not text:
        return False
    return bool(re.search(r"\.(exe|dll|bat|cmd|com|cpl|scr|sys)(\?|$)", text, re.IGNORECASE))


_MANAGED_RULE_STUBS = {
    "AWSManagedRulesCommonRuleSet": {
        "NoUserAgent_HEADER": lambda req: not req.get("headers", {}).get("user-agent"),
        "UserAgent_BadBots_HEADER": lambda req: _is_bad_bot(req.get("headers", {}).get("user-agent", "")),
        "CrossSiteScripting_BODY": lambda req: _has_xss_pattern(req.get("body", "")),
        "CrossSiteScripting_QUERYARGUMENTS": lambda req: _has_xss_pattern(req.get("query_string", "")),
        "CrossSiteScripting_URIPATH": lambda req: _has_xss_pattern(req.get("uri", "")),
        "CrossSiteScripting_COOKIE": lambda req: _has_xss_pattern(req.get("headers", {}).get("cookie", "")),
        "GenericLFI_QUERYARGUMENTS": lambda req: _has_lfi_pattern(req.get("query_string", "")),
        "GenericLFI_URIPATH": lambda req: _has_lfi_pattern(req.get("uri", "")),
        "GenericLFI_BODY": lambda req: _has_lfi_pattern(str(req.get("body", ""))),
        "RestrictedExtensions_URIPATH": lambda req: _has_restricted_ext(req.get("uri", "")),
        "RestrictedExtensions_QUERYARGUMENTS": lambda req: _has_restricted_ext(req.get("query_string", "")),
        "EC2MetaDataSSRF_BODY": lambda req: _has_ssrf_pattern(str(req.get("body", ""))),
        "EC2MetaDataSSRF_COOKIE": lambda req: _has_ssrf_pattern(req.get("headers", {}).get("cookie", "")),
        "EC2MetaDataSSRF_URIPATH": lambda req: _has_ssrf_pattern(req.get("uri", "")),
        "EC2MetaDataSSRF_QUERYARGUMENTS": lambda req: _has_ssrf_pattern(req.get("query_string", "")),
        "GenericRFI_QUERYARGUMENTS": lambda req: _has_rfi_pattern(req.get("query_string", "")),
        "GenericRFI_BODY": lambda req: _has_rfi_pattern(str(req.get("body", ""))),
        "GenericRFI_URIPATH": lambda req: _has_rfi_pattern(req.get("uri", "")),
        "SizeRestrictions_QUERYSTRING": lambda req: len(req.get("query_string", "")) > 2048,
        "SizeRestrictions_Cookie_HEADER": lambda req: len(req.get("headers", {}).get("cookie", "")) > 10240,
        "SizeRestrictions_BODY": lambda req: len(str(req.get("body", ""))) > 8192,
        "SizeRestrictions_URIPATH": lambda req: len(req.get("uri", "")) > 1024,
    },
    "AWSManagedRulesSQLiRuleSet": {
        "SQLi_QUERYARGUMENTS": lambda req: _has_sqli_pattern(req.get("query_string", "")),
        "SQLi_BODY": lambda req: _has_sqli_pattern(req.get("body", "")),
        "SQLi_URIPATH": lambda req: _has_sqli_pattern(req.get("uri", "")),
        "SQLi_COOKIE": lambda req: _has_sqli_pattern(req.get("headers", {}).get("cookie", "")),
    },
    "AWSManagedRulesKnownBadInputsRuleSet": {
        "Log4JRCE_QUERYSTRING": lambda req: "jndi:" in str(req.get("query_string", "")).lower(),
        "Log4JRCE_BODY": lambda req: "jndi:" in str(req.get("body", "")).lower(),
        "Log4JRCE_HEADER": lambda req: any("jndi:" in v.lower() for v in req.get("headers", {}).values()),
    },
    "AWSManagedRulesLinuxRuleSet": {
        "LFI_URIPATH": lambda req: _has_lfi_pattern(req.get("uri", "")),
        "LFI_QUERYSTRING": lambda req: _has_lfi_pattern(req.get("query_string", "")),
    },
    "AWSManagedRulesAmazonIpReputationList": {
        "AWSManagedIPReputationList": lambda req: False,  # Stub: never matches (no real IP DB)
    },
}


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate_request(web_acl_arn, request_info):
    """
    Evaluate a request against all rules of a WebACL.

    Args:
        web_acl_arn: ARN of the WebACL
        request_info: dict with client_ip, country, method, uri, headers, query_string, body

    Returns:
        WafResult with action, labels, terminating rule info, etc.
    """
    from ministack.services import waf

    # Find ACL by ARN
    acl = None
    for a in waf._web_acls.values():
        if a["ARN"] == web_acl_arn:
            acl = a
            break
    if not acl:
        return WafResult(action="ALLOW")

    result = WafResult(source_id=web_acl_arn)
    accumulated_labels = []
    non_terminating = []

    # Sort rules by priority
    rules = sorted(acl.get("Rules", []), key=lambda r: r.get("Priority", 0))

    for rule in rules:
        rule_name = rule.get("Name", "")
        rule_stmt = rule.get("Statement", {})
        override_action = rule.get("OverrideAction")
        rule_action_cfg = rule.get("Action", {})

        # Inject rule name for rate-based tracking
        if "RateBasedStatement" in rule_stmt or "rate_based_statement" in rule_stmt:
            rb_key = "RateBasedStatement" if "RateBasedStatement" in rule_stmt else "rate_based_statement"
            rule_stmt[rb_key]["_rule_name"] = rule_name

        matched, new_labels = _evaluate_statement(rule_stmt, request_info, accumulated_labels)
        accumulated_labels.extend(new_labels)

        # Apply rule labels if matched
        if matched:
            for rl in rule.get("RuleLabels", []):
                lbl = rl.get("Name", "")
                if lbl and lbl not in accumulated_labels:
                    accumulated_labels.append(lbl)

        if not matched:
            continue

        # Determine effective action
        if override_action is not None:
            # OverrideAction is used for rule group references / managed rules
            if "Count" in override_action or "count" in override_action:
                # Count override — convert any group action to COUNT (non-terminating)
                non_terminating.append({"id": rule_name, "action": "COUNT"})
                continue
            elif "None" in override_action or "none" in override_action:
                # "None" means use the managed group's own action
                # If matched=True from managed group, that means a terminating sub-rule fired → BLOCK
                result.action = "BLOCK"
                result.terminating_rule_id = rule_name
                result.terminating_rule_type = "MANAGED_RULE_GROUP"
                result.labels = accumulated_labels
                result.non_terminating_rules = non_terminating
                return result

        # Check rule action
        if "Block" in rule_action_cfg or "block" in rule_action_cfg:
            result.action = "BLOCK"
            result.terminating_rule_id = rule_name
            block_cfg = rule_action_cfg.get("Block") or rule_action_cfg.get("block", {})
            custom_resp = block_cfg.get("CustomResponse", block_cfg.get("custom_response", {}))
            if custom_resp:
                result.custom_response_code = int(custom_resp.get("ResponseCode", custom_resp.get("response_code", 403)))
            # Determine rule type
            if "RateBasedStatement" in rule.get("Statement", {}) or "rate_based_statement" in rule.get("Statement", {}):
                result.terminating_rule_type = "RATE_BASED"
                result.rate_based_rules.append({"id": rule_name, "key": "IP", "limit": 0})
            else:
                result.terminating_rule_type = "REGULAR"
            result.labels = accumulated_labels
            result.non_terminating_rules = non_terminating
            return result

        elif "Count" in rule_action_cfg or "count" in rule_action_cfg:
            non_terminating.append({"id": rule_name, "action": "COUNT"})
            # Extract InsertHeaders from COUNT action
            count_cfg = rule_action_cfg.get("Count") or rule_action_cfg.get("count", {})
            if isinstance(count_cfg, dict):
                crh = count_cfg.get("CustomRequestHandling", count_cfg.get("custom_request_handling", {}))
                if crh:
                    for h in crh.get("InsertHeaders", crh.get("insert_headers", [])):
                        hdr_name = h.get("Name", h.get("name", ""))
                        hdr_val = h.get("Value", h.get("value", ""))
                        if hdr_name:
                            result.inserted_headers.append({"name": hdr_name, "value": hdr_val})
            continue

        elif "Allow" in rule_action_cfg or "allow" in rule_action_cfg:
            result.action = "ALLOW"
            result.terminating_rule_id = rule_name
            result.terminating_rule_type = "REGULAR"
            # Extract InsertHeaders from ALLOW action
            allow_cfg = rule_action_cfg.get("Allow") or rule_action_cfg.get("allow", {})
            if isinstance(allow_cfg, dict):
                crh = allow_cfg.get("CustomRequestHandling", allow_cfg.get("custom_request_handling", {}))
                if crh:
                    for h in crh.get("InsertHeaders", crh.get("insert_headers", [])):
                        hdr_name = h.get("Name", h.get("name", ""))
                        hdr_val = h.get("Value", h.get("value", ""))
                        if hdr_name:
                            result.inserted_headers.append({"name": hdr_name, "value": hdr_val})
            result.labels = accumulated_labels
            result.non_terminating_rules = non_terminating
            return result

    # No rule terminated — apply default action
    default_action = acl.get("DefaultAction", {})
    if "Block" in default_action or "block" in default_action:
        result.action = "BLOCK"
    else:
        result.action = "ALLOW"
    result.terminating_rule_id = "Default_Action"
    result.terminating_rule_type = "REGULAR"
    result.labels = accumulated_labels
    result.non_terminating_rules = non_terminating
    return result


# ---------------------------------------------------------------------------
# WAF Log Writer → S3
# ---------------------------------------------------------------------------

def write_waf_log(web_acl_arn, request_info, waf_result):
    """Write a WAF log entry in AWS WAF format and save to S3."""
    from ministack.services import waf

    # Parse ACL name from ARN: arn:...:webacl/{name}/{id}
    arn_parts = web_acl_arn.split("/")
    acl_name = arn_parts[-2] if len(arn_parts) >= 2 else "unknown"

    log_entry = {
        "timestamp": int(time.time() * 1000),
        "formatVersion": 1,
        "webaclId": web_acl_arn,
        "terminatingRuleId": waf_result.terminating_rule_id or "Default_Action",
        "terminatingRuleType": waf_result.terminating_rule_type or "REGULAR",
        "action": waf_result.action,
        "terminatingRuleMatchDetails": [],
        "httpSourceName": "ALB",
        "httpSourceId": waf_result.source_id or "",
        "ruleGroupList": [],
        "rateBasedRuleList": [
            {"rateBasedRuleId": r["id"], "limitKey": r.get("key", "IP"),
             "maxRateAllowed": r.get("limit", 0)}
            for r in waf_result.rate_based_rules
        ],
        "nonTerminatingMatchingRules": [
            {"ruleId": r["id"], "action": "COUNT", "ruleMatchDetails": []}
            for r in waf_result.non_terminating_rules
        ],
        "requestHeadersInserted": waf_result.inserted_headers or None,
        "responseCodeSent": waf_result.custom_response_code or None,
        "httpRequest": {
            "clientIp": request_info.get("client_ip", "127.0.0.1"),
            "country": request_info.get("country", ""),
            "headers": [
                {"name": k, "value": v}
                for k, v in list(request_info.get("headers", {}).items())[:50]
            ],
            "uri": request_info.get("uri", "/"),
            "args": request_info.get("query_string", ""),
            "httpVersion": "HTTP/1.1",
            "httpMethod": request_info.get("method", "GET"),
            "requestId": new_uuid(),
        },
        "labels": [{"name": l} for l in (waf_result.labels or [])],
        "captchaResponse": {"responseCode": 0, "solveTimestamp": 0},
        "challengeResponse": {"responseCode": 0, "solveTimestamp": 0},
        "ja3Fingerprint": "",
    }

    # Find logging config
    log_config = waf._logging_configs.get(web_acl_arn)
    if not log_config:
        logger.debug("No logging config for %s, skipping log write", web_acl_arn)
        return

    destinations = log_config.get("LogDestinationConfigs", [])
    if not destinations:
        return

    bucket_arn = destinations[0]
    # S3 bucket ARN: arn:aws:s3:::bucket-name
    bucket_name = bucket_arn.split(":")[-1] if ":" in bucket_arn else bucket_arn

    now = time.gmtime()
    s3_key = (
        f"AWSLogs/{ACCOUNT_ID}/WAFLogs/{REGION}/{acl_name}/"
        f"{now.tm_year:04d}/{now.tm_mon:02d}/{now.tm_mday:02d}/{now.tm_hour:02d}/"
        f"waf-log-{new_uuid()}.json"
    )

    try:
        from ministack.services import s3
        log_bytes = json.dumps(log_entry).encode("utf-8")
        s3._put_object(bucket_name, s3_key, log_bytes, {})

        # Also persist to disk so Athena/DuckDB can read it
        import os
        disk_path = os.path.join(s3.DATA_DIR, bucket_name, s3_key)
        os.makedirs(os.path.dirname(disk_path), exist_ok=True)
        with open(disk_path, "wb") as f:
            f.write(log_bytes)

        logger.debug("WAF log written to s3://%s/%s", bucket_name, s3_key)
    except Exception as e:
        logger.warning("Failed to write WAF log to S3: %s", e)


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def reset():
    _rate_counters.clear()
