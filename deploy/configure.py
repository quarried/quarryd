#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlparse


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def quoted(value):
    return json.dumps(str(value), ensure_ascii=False)


def render_config():
    node_id = required("QUARRY_NODE_ID")
    endpoints = json.loads(required("QUARRY_COORDINATOR_ENDPOINTS"))
    if not isinstance(endpoints, list) or not endpoints or any(
        not isinstance(endpoint, str) or urlparse(endpoint).scheme != "https"
        or not urlparse(endpoint).hostname for endpoint in endpoints
    ):
        raise ValueError("QUARRY_COORDINATOR_ENDPOINTS must be a JSON array of HTTPS URLs")
    pool = [str(ipaddress.IPv4Network(value.strip(), strict=True)) for value in
            required("QUARRY_PUBLIC_IPV4_POOL").split(",")]
    if any(network.num_addresses > 65536 for network in map(ipaddress.IPv4Network, pool)):
        raise ValueError("public IPv4 CIDRs must not be larger than /16")
    uplink = required("QUARRY_UPLINK_INTERFACE")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", uplink):
        raise ValueError("QUARRY_UPLINK_INTERFACE must name a Linux network interface")
    arp = os.environ.get("QUARRY_PUBLIC_IPV4_ARP", "routed")
    if arp not in {"routed", "proxy"}:
        raise ValueError("QUARRY_PUBLIC_IPV4_ARP must be routed or proxy")
    public_key_file = os.environ.get("QUARRY_ARTIFACT_PUBLIC_KEY_FILE", "")
    if public_key_file:
        keys = [line.strip() for line in Path(public_key_file).read_text().splitlines()
                if line.strip() and not line.startswith("untrusted comment:")]
        if len(keys) != 1:
            raise ValueError("QUARRY_ARTIFACT_PUBLIC_KEY_FILE must contain one Minisign public key")
        public_key = keys[0]
    else:
        public_key = required("QUARRY_ARTIFACT_PUBLIC_KEY")
    decoded_key = base64.b64decode(public_key, validate=True)
    if len(decoded_key) != 42 or decoded_key[:2] != b"Ed":
        raise ValueError("artifact public key must be a Minisign Ed25519 public key")
    lines = [
        f"node_id = {quoted(node_id)}",
        f"endpoints = {json.dumps(endpoints)}",
        'state_dir = "/var/lib/quarryd"',
        'ca_cert = "/etc/quarryd/coordinator-ca.crt"',
        'join_token_file = "/etc/quarryd/join-token"',
        'metrics_addr = "127.0.0.1:9478"',
        "lease_ttl_secs = 60",
        f"public_ipv4_pool = {json.dumps(pool)}",
        f"uplink_interface = {quoted(uplink)}",
        f"public_ipv4_arp = {quoted(arp)}",
        "", "[reservation]", "vcpus = 2", "memory_mib = 2048", "disk_gib = 10",
        "", "[sandbox]", 'backend = "auto"',
        "", "[volume]", 'backend = "lvm-thin"',
        f"volume_group = {quoted(os.environ.get('QUARRY_VOLUME_GROUP', 'quarry'))}",
        f"thin_pool = {quoted(os.environ.get('QUARRY_THIN_POOL', 'instances'))}",
        "", "[network]", 'backend = "host"',
    ]
    for section, prefix in (("artifacts", "ARTIFACTS"), ("snapshots", "SNAPSHOTS")):
        lines += ["", f"[{section}]", f"bucket = {quoted(required(f'QUARRY_{prefix}_BUCKET'))}"]
        region = os.environ.get(f"QUARRY_{prefix}_REGION", os.environ.get("QUARRY_S3_REGION", ""))
        endpoint = os.environ.get(f"QUARRY_{prefix}_ENDPOINT", os.environ.get("QUARRY_S3_ENDPOINT", ""))
        if region:
            lines.append(f"region = {quoted(region)}")
        if endpoint:
            if urlparse(endpoint).scheme not in {"http", "https"} or not urlparse(endpoint).hostname:
                raise ValueError(f"QUARRY_{prefix}_ENDPOINT must be an HTTP(S) URL")
            lines.append(f"endpoint = {quoted(endpoint)}")
        if section == "artifacts":
            lines += [f"public_key = {quoted(public_key)}", "cache_capacity_gib = 50"]
    lines += ["", "[instances]", "stop_deadline_secs = 60"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Generate a production quarryd TOML configuration from node and storage inputs.",
        epilog="Required environment: QUARRY_NODE_ID, QUARRY_COORDINATOR_ENDPOINTS (JSON array), "
        "QUARRY_PUBLIC_IPV4_POOL (comma-separated IPv4 CIDRs), QUARRY_UPLINK_INTERFACE, "
        "QUARRY_ARTIFACTS_BUCKET, QUARRY_SNAPSHOTS_BUCKET, and QUARRY_ARTIFACT_PUBLIC_KEY "
        "or QUARRY_ARTIFACT_PUBLIC_KEY_FILE. Optional: QUARRY_PUBLIC_IPV4_ARP (routed or proxy), "
        "QUARRY_S3_REGION, QUARRY_S3_ENDPOINT, per-bucket QUARRY_ARTIFACTS_{REGION,ENDPOINT} "
        "and QUARRY_SNAPSHOTS_{REGION,ENDPOINT}, QUARRY_VOLUME_GROUP and QUARRY_THIN_POOL. "
        "The systemd unit reads AWS credentials from /etc/quarryd/object-storage.env. "
        "Place the coordinator server CA in /etc/quarryd/coordinator-ca.crt and the issued "
        "single-use join token in /etc/quarryd/join-token. Use AWS_ALLOW_HTTP=true only "
        "when the object store endpoint uses HTTP.",
    )
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    try:
        config = render_config()
        options.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=options.output.parent, delete=False) as output:
            temporary = Path(output.name)
            try:
                output.write(config.encode())
                output.flush()
                os.fsync(output.fileno())
                temporary.chmod(0o600)
                temporary.replace(options.output)
            finally:
                temporary.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
