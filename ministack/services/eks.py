"""
EKS (Elastic Kubernetes Service) Emulator.
REST JSON API — path-based routing.
Supports: CreateCluster, DescribeCluster, DeleteCluster, ListClusters,
          CreateNodegroup, DescribeNodegroup, DeleteNodegroup, ListNodegroups,
          CreateAddon, DescribeAddon, DeleteAddon, ListAddons,
          CreateFargateProfile, DescribeFargateProfile, DeleteFargateProfile, ListFargateProfiles,
          TagResource, UntagResource, ListTagsForResource,
          UpdateClusterConfig, UpdateNodegroupConfig, DescribeUpdate.

Control-plane only — no real Kubernetes clusters are created.
"""

import copy
import json
import logging
import os
import re

from ministack.core.persistence import load_state
from ministack.core.responses import (
    error_response_json,
    json_response,
    new_uuid,
    now_iso,
)

logger = logging.getLogger("eks")

ACCOUNT_ID = os.environ.get("MINISTACK_ACCOUNT_ID", "000000000000")
REGION = os.environ.get("MINISTACK_REGION", "us-east-1")

_clusters: dict = {}        # name → cluster metadata
_nodegroups: dict = {}      # (cluster_name, ng_name) → nodegroup metadata
_addons: dict = {}          # (cluster_name, addon_name) → addon metadata
_fargate_profiles: dict = {}  # (cluster_name, fp_name) → fargate profile
_tags: dict = {}            # arn → {key: value}
_updates: dict = {}         # update_id → update metadata


# ── Persistence ────────────────────────────────────────────

def get_state():
    return {
        "clusters": copy.deepcopy(_clusters),
        "nodegroups": copy.deepcopy(_nodegroups),
        "addons": copy.deepcopy(_addons),
        "fargate_profiles": copy.deepcopy(_fargate_profiles),
        "tags": copy.deepcopy(_tags),
        "updates": copy.deepcopy(_updates),
    }


def restore_state(data):
    if not data:
        return
    _clusters.update(data.get("clusters", {}))
    _nodegroups.update(data.get("nodegroups", {}))
    _addons.update(data.get("addons", {}))
    _fargate_profiles.update(data.get("fargate_profiles", {}))
    _tags.update(data.get("tags", {}))
    _updates.update(data.get("updates", {}))


_restored = load_state("eks")
if _restored:
    restore_state(_restored)


# ── Helpers ────────────────────────────────────────────────

def _cluster_arn(name):
    return f"arn:aws:eks:{REGION}:{ACCOUNT_ID}:cluster/{name}"


def _nodegroup_arn(cluster_name, ng_name):
    return f"arn:aws:eks:{REGION}:{ACCOUNT_ID}:nodegroup/{cluster_name}/{ng_name}/{new_uuid()[:8]}"


def _addon_arn(cluster_name, addon_name):
    return f"arn:aws:eks:{REGION}:{ACCOUNT_ID}:addon/{cluster_name}/{addon_name}/{new_uuid()[:8]}"


def _fargate_arn(cluster_name, fp_name):
    return f"arn:aws:eks:{REGION}:{ACCOUNT_ID}:fargateprofile/{cluster_name}/{fp_name}/{new_uuid()[:8]}"


def _make_update(update_type, params=None):
    uid = new_uuid()
    update = {
        "id": uid,
        "status": "Successful",
        "type": update_type,
        "params": params or [],
        "createdAt": now_iso(),
        "errors": [],
    }
    _updates[uid] = update
    return update


def _oidc_issuer(name):
    return f"https://oidc.eks.{REGION}.amazonaws.com/id/{new_uuid().replace('-', '').upper()[:32]}"


def _endpoint(name):
    return f"https://{new_uuid()[:12]}.gr7.{REGION}.eks.amazonaws.com"


def _certificate_authority():
    import base64
    # Return a plausible base64-encoded stub certificate
    stub = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----\n"
    return base64.b64encode(stub).decode()


# ── Cluster CRUD ───────────────────────────────────────────

def _create_cluster(data):
    name = data.get("name")
    if not name:
        return error_response_json("InvalidParameterException", "Cluster name is required", 400)

    if name in _clusters:
        return error_response_json("ResourceInUseException", f"Cluster already exists with name: {name}", 409)

    role_arn = data.get("roleArn", f"arn:aws:iam::{ACCOUNT_ID}:role/eks-service-role")
    vpc_config = data.get("resourcesVpcConfig", {})
    version = data.get("version", "1.31")
    tags = data.get("tags", {})

    arn = _cluster_arn(name)
    now = now_iso()
    oidc = _oidc_issuer(name)
    endpoint = _endpoint(name)
    ca = _certificate_authority()

    cluster = {
        "name": name,
        "arn": arn,
        "createdAt": now,
        "version": version,
        "roleArn": role_arn,
        "resourcesVpcConfig": {
            "subnetIds": vpc_config.get("subnetIds", []),
            "securityGroupIds": vpc_config.get("securityGroupIds", []),
            "clusterSecurityGroupId": f"sg-{new_uuid()[:8]}",
            "vpcId": vpc_config.get("vpcId", f"vpc-{new_uuid()[:8]}"),
            "endpointPublicAccess": vpc_config.get("endpointPublicAccess", True),
            "endpointPrivateAccess": vpc_config.get("endpointPrivateAccess", False),
            "publicAccessCidrs": vpc_config.get("publicAccessCidrs", ["0.0.0.0/0"]),
        },
        "kubernetesNetworkConfig": {
            "serviceIpv4Cidr": data.get("kubernetesNetworkConfig", {}).get("serviceIpv4Cidr", "10.100.0.0/16"),
            "ipFamily": data.get("kubernetesNetworkConfig", {}).get("ipFamily", "ipv4"),
        },
        "logging": data.get("logging", {"clusterLogging": [{"types": ["api", "audit", "authenticator", "controllerManager", "scheduler"], "enabled": False}]}),
        "identity": {
            "oidc": {"issuer": oidc},
        },
        "status": "ACTIVE",
        "certificateAuthority": {"data": ca},
        "endpoint": endpoint,
        "platformVersion": f"eks.{version.replace('.', '-')}",
        "tags": tags,
        "encryptionConfig": data.get("encryptionConfig", []),
        "accessConfig": data.get("accessConfig", {
            "authenticationMode": "API_AND_CONFIG_MAP",
        }),
    }

    _clusters[name] = cluster
    if tags:
        _tags[arn] = tags

    logger.info("Created EKS cluster: %s", name)
    return json_response({"cluster": cluster}, 200)


def _describe_cluster(name):
    cluster = _clusters.get(name)
    if not cluster:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {name}", 404)
    return json_response({"cluster": cluster}, 200)


def _delete_cluster(name):
    cluster = _clusters.get(name)
    if not cluster:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {name}", 404)

    # Check for active nodegroups
    active_ngs = [(cn, ng) for (cn, ng) in _nodegroups if cn == name]
    if active_ngs:
        return error_response_json("ResourceInUseException",
                                   "Cluster has active nodegroups. Delete nodegroups before deleting cluster.", 409)

    cluster["status"] = "DELETING"
    arn = cluster["arn"]
    del _clusters[name]
    _tags.pop(arn, None)

    # Clean up addons and fargate profiles
    for key in list(_addons.keys()):
        if key[0] == name:
            del _addons[key]
    for key in list(_fargate_profiles.keys()):
        if key[0] == name:
            del _fargate_profiles[key]

    logger.info("Deleted EKS cluster: %s", name)
    return json_response({"cluster": cluster}, 200)


def _list_clusters(data):
    names = sorted(_clusters.keys())
    max_results = int(data.get("maxResults", 100))
    next_token = data.get("nextToken")

    start = 0
    if next_token:
        try:
            start = int(next_token)
        except ValueError:
            start = 0

    page = names[start:start + max_results]
    resp = {"clusters": page}
    if start + max_results < len(names):
        resp["nextToken"] = str(start + max_results)

    return json_response(resp, 200)


def _update_cluster_config(name, data):
    cluster = _clusters.get(name)
    if not cluster:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {name}", 404)

    params = []
    if "resourcesVpcConfig" in data:
        vpc = data["resourcesVpcConfig"]
        if "endpointPublicAccess" in vpc:
            cluster["resourcesVpcConfig"]["endpointPublicAccess"] = vpc["endpointPublicAccess"]
            params.append({"type": "EndpointPublicAccess", "value": str(vpc["endpointPublicAccess"])})
        if "endpointPrivateAccess" in vpc:
            cluster["resourcesVpcConfig"]["endpointPrivateAccess"] = vpc["endpointPrivateAccess"]
            params.append({"type": "EndpointPrivateAccess", "value": str(vpc["endpointPrivateAccess"])})
        if "publicAccessCidrs" in vpc:
            cluster["resourcesVpcConfig"]["publicAccessCidrs"] = vpc["publicAccessCidrs"]

    if "logging" in data:
        cluster["logging"] = data["logging"]
        params.append({"type": "Logging", "value": "enabled"})

    update = _make_update("ConfigUpdate", params)
    return json_response({"update": update}, 200)


# ── Nodegroup CRUD ─────────────────────────────────────────

def _create_nodegroup(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    ng_name = data.get("nodegroupName")
    if not ng_name:
        return error_response_json("InvalidParameterException", "Nodegroup name is required", 400)

    key = (cluster_name, ng_name)
    if key in _nodegroups:
        return error_response_json("ResourceInUseException", f"Nodegroup already exists with name: {ng_name}", 409)

    arn = _nodegroup_arn(cluster_name, ng_name)
    now = now_iso()
    tags = data.get("tags", {})

    scaling = data.get("scalingConfig", {})
    nodegroup = {
        "nodegroupName": ng_name,
        "nodegroupArn": arn,
        "clusterName": cluster_name,
        "version": data.get("version", _clusters[cluster_name].get("version", "1.31")),
        "releaseVersion": data.get("releaseVersion", "1.31.0-20240101"),
        "createdAt": now,
        "modifiedAt": now,
        "status": "ACTIVE",
        "capacityType": data.get("capacityType", "ON_DEMAND"),
        "scalingConfig": {
            "minSize": scaling.get("minSize", 1),
            "maxSize": scaling.get("maxSize", 2),
            "desiredSize": scaling.get("desiredSize", 2),
        },
        "instanceTypes": data.get("instanceTypes", ["t3.medium"]),
        "subnets": data.get("subnets", []),
        "amiType": data.get("amiType", "AL2_x86_64"),
        "nodeRole": data.get("nodeRole", f"arn:aws:iam::{ACCOUNT_ID}:role/eks-node-role"),
        "labels": data.get("labels", {}),
        "taints": data.get("taints", []),
        "diskSize": data.get("diskSize", 20),
        "health": {"issues": []},
        "updateConfig": data.get("updateConfig", {"maxUnavailable": 1}),
        "launchTemplate": data.get("launchTemplate"),
        "tags": tags,
        "resources": {
            "autoScalingGroups": [{"name": f"eks-{ng_name}-{new_uuid()[:8]}"}],
            "remoteAccessSecurityGroup": f"sg-{new_uuid()[:8]}",
        },
    }

    _nodegroups[key] = nodegroup
    if tags:
        _tags[arn] = tags

    logger.info("Created EKS nodegroup: %s/%s", cluster_name, ng_name)
    return json_response({"nodegroup": nodegroup}, 200)


def _describe_nodegroup(cluster_name, ng_name):
    key = (cluster_name, ng_name)
    ng = _nodegroups.get(key)
    if not ng:
        return error_response_json("ResourceNotFoundException",
                                   f"No nodegroup found for name: {ng_name} in cluster: {cluster_name}", 404)
    return json_response({"nodegroup": ng}, 200)


def _delete_nodegroup(cluster_name, ng_name):
    key = (cluster_name, ng_name)
    ng = _nodegroups.get(key)
    if not ng:
        return error_response_json("ResourceNotFoundException",
                                   f"No nodegroup found for name: {ng_name} in cluster: {cluster_name}", 404)

    ng["status"] = "DELETING"
    arn = ng["nodegroupArn"]
    del _nodegroups[key]
    _tags.pop(arn, None)

    logger.info("Deleted EKS nodegroup: %s/%s", cluster_name, ng_name)
    return json_response({"nodegroup": ng}, 200)


def _list_nodegroups(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    names = sorted(ng for (cn, ng) in _nodegroups if cn == cluster_name)
    max_results = int(data.get("maxResults", 100))
    next_token = data.get("nextToken")

    start = 0
    if next_token:
        try:
            start = int(next_token)
        except ValueError:
            start = 0

    page = names[start:start + max_results]
    resp = {"nodegroups": page}
    if start + max_results < len(names):
        resp["nextToken"] = str(start + max_results)

    return json_response(resp, 200)


def _update_nodegroup_config(cluster_name, ng_name, data):
    key = (cluster_name, ng_name)
    ng = _nodegroups.get(key)
    if not ng:
        return error_response_json("ResourceNotFoundException",
                                   f"No nodegroup found for name: {ng_name} in cluster: {cluster_name}", 404)

    params = []
    if "scalingConfig" in data:
        sc = data["scalingConfig"]
        for field in ("minSize", "maxSize", "desiredSize"):
            if field in sc:
                ng["scalingConfig"][field] = sc[field]
                params.append({"type": field, "value": str(sc[field])})

    if "labels" in data:
        add_labels = data["labels"].get("addOrUpdateLabels", {})
        remove_labels = data["labels"].get("removeLabels", [])
        ng["labels"].update(add_labels)
        for k in remove_labels:
            ng["labels"].pop(k, None)

    if "taints" in data:
        add_taints = data["taints"].get("addOrUpdateTaints", [])
        remove_taints = data["taints"].get("removeTaints", [])
        for t in add_taints:
            ng["taints"] = [x for x in ng["taints"] if x.get("key") != t.get("key")]
            ng["taints"].append(t)
        for t in remove_taints:
            ng["taints"] = [x for x in ng["taints"] if x.get("key") != t.get("key")]

    ng["modifiedAt"] = now_iso()
    update = _make_update("ConfigUpdate", params)
    return json_response({"update": update}, 200)


# ── Addon CRUD ─────────────────────────────────────────────

_DEFAULT_ADDONS = {
    "vpc-cni": {"defaultVersion": "v1.18.1-eksbuild.1"},
    "coredns": {"defaultVersion": "v1.11.1-eksbuild.9"},
    "kube-proxy": {"defaultVersion": "v1.31.0-eksbuild.5"},
    "aws-ebs-csi-driver": {"defaultVersion": "v1.35.0-eksbuild.1"},
}


def _create_addon(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    addon_name = data.get("addonName")
    if not addon_name:
        return error_response_json("InvalidParameterException", "Addon name is required", 400)

    key = (cluster_name, addon_name)
    if key in _addons:
        return error_response_json("ResourceInUseException", f"Addon already exists: {addon_name}", 409)

    arn = _addon_arn(cluster_name, addon_name)
    now = now_iso()
    tags = data.get("tags", {})

    default = _DEFAULT_ADDONS.get(addon_name, {})
    addon = {
        "addonName": addon_name,
        "addonArn": arn,
        "clusterName": cluster_name,
        "status": "ACTIVE",
        "addonVersion": data.get("addonVersion", default.get("defaultVersion", "v1.0.0")),
        "createdAt": now,
        "modifiedAt": now,
        "serviceAccountRoleArn": data.get("serviceAccountRoleArn", ""),
        "tags": tags,
        "configurationValues": data.get("configurationValues", ""),
        "health": {"issues": []},
    }

    _addons[key] = addon
    if tags:
        _tags[arn] = tags

    logger.info("Created EKS addon: %s/%s", cluster_name, addon_name)
    return json_response({"addon": addon}, 200)


def _describe_addon(cluster_name, addon_name):
    key = (cluster_name, addon_name)
    addon = _addons.get(key)
    if not addon:
        return error_response_json("ResourceNotFoundException",
                                   f"No addon found for name: {addon_name} in cluster: {cluster_name}", 404)
    return json_response({"addon": addon}, 200)


def _delete_addon(cluster_name, addon_name):
    key = (cluster_name, addon_name)
    addon = _addons.get(key)
    if not addon:
        return error_response_json("ResourceNotFoundException",
                                   f"No addon found for name: {addon_name} in cluster: {cluster_name}", 404)

    addon["status"] = "DELETING"
    arn = addon["addonArn"]
    del _addons[key]
    _tags.pop(arn, None)

    logger.info("Deleted EKS addon: %s/%s", cluster_name, addon_name)
    return json_response({"addon": addon}, 200)


def _list_addons(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    names = sorted(an for (cn, an) in _addons if cn == cluster_name)
    max_results = int(data.get("maxResults", 100))
    next_token = data.get("nextToken")

    start = 0
    if next_token:
        try:
            start = int(next_token)
        except ValueError:
            start = 0

    page = names[start:start + max_results]
    resp = {"addons": page}
    if start + max_results < len(names):
        resp["nextToken"] = str(start + max_results)

    return json_response(resp, 200)


# ── Fargate Profile CRUD ──────────────────────────────────

def _create_fargate_profile(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    fp_name = data.get("fargateProfileName")
    if not fp_name:
        return error_response_json("InvalidParameterException", "Fargate profile name is required", 400)

    key = (cluster_name, fp_name)
    if key in _fargate_profiles:
        return error_response_json("ResourceInUseException", f"Fargate profile already exists: {fp_name}", 409)

    arn = _fargate_arn(cluster_name, fp_name)
    now = now_iso()
    tags = data.get("tags", {})

    profile = {
        "fargateProfileName": fp_name,
        "fargateProfileArn": arn,
        "clusterName": cluster_name,
        "createdAt": now,
        "podExecutionRoleArn": data.get("podExecutionRoleArn", f"arn:aws:iam::{ACCOUNT_ID}:role/eks-fargate-role"),
        "subnets": data.get("subnets", []),
        "selectors": data.get("selectors", []),
        "status": "ACTIVE",
        "tags": tags,
    }

    _fargate_profiles[key] = profile
    if tags:
        _tags[arn] = tags

    logger.info("Created EKS Fargate profile: %s/%s", cluster_name, fp_name)
    return json_response({"fargateProfile": profile}, 200)


def _describe_fargate_profile(cluster_name, fp_name):
    key = (cluster_name, fp_name)
    fp = _fargate_profiles.get(key)
    if not fp:
        return error_response_json("ResourceNotFoundException",
                                   f"No Fargate profile found for name: {fp_name} in cluster: {cluster_name}", 404)
    return json_response({"fargateProfile": fp}, 200)


def _delete_fargate_profile(cluster_name, fp_name):
    key = (cluster_name, fp_name)
    fp = _fargate_profiles.get(key)
    if not fp:
        return error_response_json("ResourceNotFoundException",
                                   f"No Fargate profile found for name: {fp_name} in cluster: {cluster_name}", 404)

    fp["status"] = "DELETING"
    arn = fp["fargateProfileArn"]
    del _fargate_profiles[key]
    _tags.pop(arn, None)

    logger.info("Deleted EKS Fargate profile: %s/%s", cluster_name, fp_name)
    return json_response({"fargateProfile": fp}, 200)


def _list_fargate_profiles(cluster_name, data):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)

    names = sorted(fp for (cn, fp) in _fargate_profiles if cn == cluster_name)
    max_results = int(data.get("maxResults", 100))
    next_token = data.get("nextToken")

    start = 0
    if next_token:
        try:
            start = int(next_token)
        except ValueError:
            start = 0

    page = names[start:start + max_results]
    resp = {"fargateProfileNames": page}
    if start + max_results < len(names):
        resp["nextToken"] = str(start + max_results)

    return json_response(resp, 200)


# ── Tags ───────────────────────────────────────────────────

def _tag_resource(data):
    arn = data.get("resourceArn", "")
    tags = data.get("tags", {})
    if not arn:
        return error_response_json("InvalidParameterException", "resourceArn is required", 400)

    existing = _tags.get(arn, {})
    existing.update(tags)
    _tags[arn] = existing

    # Update tags in the resource itself
    _update_resource_tags(arn, existing)

    return json_response({}, 200)


def _untag_resource(data):
    arn = data.get("resourceArn", "")
    tag_keys = data.get("tagKeys", [])
    if not arn:
        return error_response_json("InvalidParameterException", "resourceArn is required", 400)

    existing = _tags.get(arn, {})
    for k in tag_keys:
        existing.pop(k, None)
    _tags[arn] = existing

    _update_resource_tags(arn, existing)

    return json_response({}, 200)


def _list_tags_for_resource(arn):
    tags = _tags.get(arn, {})
    return json_response({"tags": tags}, 200)


def _update_resource_tags(arn, tags):
    """Sync tags back to the resource object."""
    for name, cluster in _clusters.items():
        if cluster.get("arn") == arn:
            cluster["tags"] = tags
            return
    for key, ng in _nodegroups.items():
        if ng.get("nodegroupArn") == arn:
            ng["tags"] = tags
            return
    for key, addon in _addons.items():
        if addon.get("addonArn") == arn:
            addon["tags"] = tags
            return
    for key, fp in _fargate_profiles.items():
        if fp.get("fargateProfileArn") == arn:
            fp["tags"] = tags
            return


# ── Describe Update ────────────────────────────────────────

def _describe_update(cluster_name, update_id):
    if cluster_name not in _clusters:
        return error_response_json("ResourceNotFoundException", f"No cluster found for name: {cluster_name}", 404)
    update = _updates.get(update_id)
    if not update:
        return error_response_json("ResourceNotFoundException", f"No update found for id: {update_id}", 404)
    return json_response({"update": update}, 200)


# ── Request routing ────────────────────────────────────────

async def handle_request(method, path, headers, body, query_params):
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}

    if method == "GET":
        for k, v in query_params.items():
            if k not in data:
                data[k] = v[0] if isinstance(v, list) and len(v) == 1 else v

    # Strip leading slash and split
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        return error_response_json("InvalidRequest", "Missing path", 400)

    return _route(method, parts, data, query_params)


def _route(method, parts, data, query_params):
    resource = parts[0]

    # ── /clusters ──
    if resource == "clusters":
        # POST /clusters → CreateCluster
        if method == "POST" and len(parts) == 1:
            return _create_cluster(data)

        # GET /clusters → ListClusters
        if method == "GET" and len(parts) == 1:
            return _list_clusters(data)

        # GET /clusters/{name} → DescribeCluster
        if method == "GET" and len(parts) == 2:
            return _describe_cluster(parts[1])

        # DELETE /clusters/{name} → DeleteCluster
        if method == "DELETE" and len(parts) == 2:
            return _delete_cluster(parts[1])

        # PUT /clusters/{name}/config → UpdateClusterConfig
        if method == "POST" and len(parts) == 3 and parts[2] == "config":
            return _update_cluster_config(parts[1], data)

        # ── /clusters/{name}/node-groups ──
        if len(parts) >= 3 and parts[2] == "node-groups":
            cluster_name = parts[1]

            # POST /clusters/{name}/node-groups → CreateNodegroup
            if method == "POST" and len(parts) == 3:
                return _create_nodegroup(cluster_name, data)

            # GET /clusters/{name}/node-groups → ListNodegroups
            if method == "GET" and len(parts) == 3:
                return _list_nodegroups(cluster_name, data)

            # GET /clusters/{name}/node-groups/{ngName} → DescribeNodegroup
            if method == "GET" and len(parts) == 4:
                return _describe_nodegroup(cluster_name, parts[3])

            # DELETE /clusters/{name}/node-groups/{ngName} → DeleteNodegroup
            if method == "DELETE" and len(parts) == 4:
                return _delete_nodegroup(cluster_name, parts[3])

            # POST /clusters/{name}/node-groups/{ngName}/update-config → UpdateNodegroupConfig
            if method == "POST" and len(parts) == 5 and parts[4] == "update-config":
                return _update_nodegroup_config(cluster_name, parts[3], data)

        # ── /clusters/{name}/addons ──
        if len(parts) >= 3 and parts[2] == "addons":
            cluster_name = parts[1]

            # POST /clusters/{name}/addons → CreateAddon
            if method == "POST" and len(parts) == 3:
                return _create_addon(cluster_name, data)

            # GET /clusters/{name}/addons → ListAddons
            if method == "GET" and len(parts) == 3:
                return _list_addons(cluster_name, data)

            # GET /clusters/{name}/addons/{addonName} → DescribeAddon
            if method == "GET" and len(parts) == 4:
                return _describe_addon(cluster_name, parts[3])

            # DELETE /clusters/{name}/addons/{addonName} → DeleteAddon
            if method == "DELETE" and len(parts) == 4:
                return _delete_addon(cluster_name, parts[3])

        # ── /clusters/{name}/fargate-profiles ──
        if len(parts) >= 3 and parts[2] == "fargate-profiles":
            cluster_name = parts[1]

            # POST /clusters/{name}/fargate-profiles → CreateFargateProfile
            if method == "POST" and len(parts) == 3:
                return _create_fargate_profile(cluster_name, data)

            # GET /clusters/{name}/fargate-profiles → ListFargateProfiles
            if method == "GET" and len(parts) == 3:
                return _list_fargate_profiles(cluster_name, data)

            # GET /clusters/{name}/fargate-profiles/{fpName} → DescribeFargateProfile
            if method == "GET" and len(parts) == 4:
                return _describe_fargate_profile(cluster_name, parts[3])

            # DELETE /clusters/{name}/fargate-profiles/{fpName} → DeleteFargateProfile
            if method == "DELETE" and len(parts) == 4:
                return _delete_fargate_profile(cluster_name, parts[3])

        # ── /clusters/{name}/updates/{updateId} ──
        if len(parts) == 4 and parts[2] == "updates" and method == "GET":
            return _describe_update(parts[1], parts[3])

    # ── /tags/{arn+} ──
    if resource == "tags":
        arn = "/".join(parts[1:])
        # Reconstruct full ARN from URL path
        if not arn.startswith("arn:"):
            arn = "arn:" + arn

        if method == "GET":
            return _list_tags_for_resource(arn)
        if method == "POST":
            data["resourceArn"] = arn
            return _tag_resource(data)
        if method == "DELETE":
            tag_keys = data.get("tagKeys", [])
            if not tag_keys and "tagKeys" in query_params:
                tag_keys = query_params["tagKeys"] if isinstance(query_params["tagKeys"], list) else [query_params["tagKeys"]]
            return _untag_resource({"resourceArn": arn, "tagKeys": tag_keys})

    return error_response_json("InvalidRequest", f"Unknown EKS path: /{'/'.join(parts)}", 400)


def reset():
    _clusters.clear()
    _nodegroups.clear()
    _addons.clear()
    _fargate_profiles.clear()
    _tags.clear()
    _updates.clear()
    logger.info("EKS state reset")
