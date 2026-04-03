#!/usr/bin/env bash
# ═══════════════════════════════════════════════
#  MiniStack Terraform Integration Test
#  Runs: init → plan → apply → verify → destroy
#
#  Prerequisites:
#    - MiniStack running on localhost:4566
#    - Terraform installed
#
#  Usage:
#    ./run_test.sh
# ═══════════════════════════════════════════════
set -euo pipefail

ENDPOINT="${MINISTACK_ENDPOINT:-http://localhost:4566}"
DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

extract_number() {
    # Extract first number from a pattern match in text
    python3 -c "import re,sys; m=re.search(r'$1', sys.stdin.read()); print(m.group(1) if m else '0')"
}

# ── Preflight ─────────────────────────────────
info "Checking MiniStack health..."
if ! curl -sf "${ENDPOINT}/_ministack/health" > /dev/null 2>&1; then
    fail "MiniStack is not running at ${ENDPOINT}"
    echo "  Start it with: python -m uvicorn ministack.app:app --host 0.0.0.0 --port 4566"
    exit 1
fi
pass "MiniStack is healthy"

info "Resetting MiniStack state..."
curl -sf -X POST "${ENDPOINT}/_ministack/reset" > /dev/null
pass "State reset"

# ── Init ──────────────────────────────────────
cd "$DIR"
info "terraform init..."
terraform init -input=false > /dev/null 2>&1
pass "Initialized"

# ── Plan ──────────────────────────────────────
info "terraform plan..."
PLAN_OUTPUT=$(terraform plan -no-color 2>&1)
PLAN_COUNT=$(echo "$PLAN_OUTPUT" | extract_number '(\d+) to add')
pass "Plan: ${PLAN_COUNT} resources to create"

# ── Apply ─────────────────────────────────────
info "terraform apply..."
APPLY_OUTPUT=$(terraform apply -auto-approve -no-color 2>&1)

if echo "$APPLY_OUTPUT" | grep -q "Apply complete!"; then
    ADDED=$(echo "$APPLY_OUTPUT" | extract_number '(\d+) added')
    pass "Apply complete: ${ADDED} resources created"
else
    fail "Apply failed!"
    echo "$APPLY_OUTPUT" | grep -A 2 "Error:" || true
    exit 1
fi

# ── Verify via MiniStack State API ────────────
info "Verifying resources via /_ministack/state..."
STATE=$(curl -sf "${ENDPOINT}/_ministack/state")
TOTAL=$(echo "$STATE" | python3 -c "import sys,json; print(json.load(sys.stdin)['totals']['total_resources'])")
pass "MiniStack reports ${TOTAL} total resources"

# Show per-service breakdown
echo ""
echo "  Resource breakdown:"
echo "$STATE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for svc, info in sorted(data['services'].items()):
    res = info.get('resources', {})
    counts = {k: v for k, v in res.items() if isinstance(v, int) and v > 0}
    if counts:
        items = ', '.join(f'{v} {k}' for k, v in counts.items())
        print(f'    {svc:20s} {items}')
"
echo ""

# ── Destroy ───────────────────────────────────
info "terraform destroy..."
DESTROY_OUTPUT=$(terraform destroy -auto-approve -no-color 2>&1)

if echo "$DESTROY_OUTPUT" | grep -q "Destroy complete!"; then
    DESTROYED=$(echo "$DESTROY_OUTPUT" | extract_number '(\d+) destroyed')
    pass "Destroy complete: ${DESTROYED} resources removed"
else
    fail "Destroy failed!"
    echo "$DESTROY_OUTPUT" | grep -A 2 "Error:" || true
    exit 1
fi

# ── Post-destroy verification ─────────────────
info "Verifying cleanup via /_ministack/state..."
STATE_AFTER=$(curl -sf "${ENDPOINT}/_ministack/state")
REMAINING=$(echo "$STATE_AFTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
# EC2 default VPC resources are always present — exclude them
count = 0
for svc, info in data['services'].items():
    if svc == 'ec2':
        continue
    for k, v in info.get('resources', {}).items():
        if isinstance(v, int) and v > 0:
            count += v
print(count)
")

if [ "$REMAINING" -eq 0 ]; then
    pass "All resources cleaned up (EC2 default VPC excluded)"
else
    fail "${REMAINING} resources still remain after destroy"
fi

# ── Cleanup local state ───────────────────────
rm -rf .terraform terraform.tfstate* .terraform.lock.hcl

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MiniStack Terraform test completed!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
