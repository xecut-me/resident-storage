#!/usr/bin/env python3
import json
import re
import subprocess
import tempfile
from pathlib import Path

CONFIG_PATH = Path("./config.json")
DATA_DIR = Path("./resident-data")
WG_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_peers() -> dict[str, str]:
    """Load peers from last.json and return dict of ip -> wg_public_key."""
    last_path = DATA_DIR / "last.json"
    if not last_path.exists():
        return {}

    data = json.loads(last_path.read_text())
    peers = {}
    for account in data.get("accounts", []):
        for vpn in account.get("vpn", []):
            peers[vpn["ip"]] = vpn["wg_public_key"]
    return peers


def validate_ip(ip: str) -> bool:
    pattern = r"^192\.168\.11\.(\d+)$"
    match = re.match(pattern, ip)
    if not match:
        return False
    x = int(match.group(1))
    return 2 <= x <= 250


def validate_key(key: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9+/]{43}=?$", key))


def validate_peers(peers: dict[str, str]) -> bool:
    ips = list(peers.keys())
    keys = list(peers.values())

    if len(ips) != len(set(ips)):
        print("Error: duplicate IPs detected")
        return False

    if len(keys) != len(set(keys)):
        print("Error: duplicate keys detected")
        return False

    for ip in ips:
        if not validate_ip(ip):
            print(f"Error: invalid IP {ip}")
            return False

    for key in keys:
        if not validate_key(key):
            print(f"Error: invalid key {key}")
            return False

    return True


def generate_config(config: dict, peers: dict[str, str]) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {config['vpn_private_key']}",
        "Address = 192.168.11.1/24",
        f"ListenPort = {config['vpn_port']}",
        "",
        "PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
    ]

    # Add peers (admin is injected into peers dict in main())
    for ip, key in sorted(peers.items()):
        lines.extend([
            "",
            "[Peer]",
            f"PublicKey = {key}",
            f"AllowedIPs = {ip}/32",
        ])

    return "\n".join(lines) + "\n"


def verify_config(path: str) -> bool:
    try:
        result = subprocess.run(
            ["sudo", "wg-quick", "strip", path],
            capture_output=True,
            timeout=30
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Config verification failed: {e}")
        return False


def backup_current_config() -> str | None:
    if not WG_CONFIG_PATH.exists():
        return None
    return WG_CONFIG_PATH.read_text()


def write_config(content: str) -> bool:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(content)
        temp_path = f.name

    try:
        result = subprocess.run(
            ["sudo", "mv", temp_path, str(WG_CONFIG_PATH)],
            capture_output=True,
            timeout=30
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Failed to move config: {e}")
        Path(temp_path).unlink(missing_ok=True)
        return False


def reload_wireguard() -> bool:
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "reload", "wg-quick@wg0"],
            capture_output=True,
            timeout=30
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Failed to reload WireGuard: {e}")
        return False


def revert_config(backup: str | None):
    if backup is None:
        return
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(backup)
        temp_path = f.name
    subprocess.run(["sudo", "mv", temp_path, str(WG_CONFIG_PATH)], timeout=30)


def main():
    config = load_config()

    required_keys = ["vpn_private_key", "vpn_port", "vpn_admin_ip", "vpn_admin_public_key"]
    for key in required_keys:
        if key not in config:
            print(f"Error: missing config key {key}")
            return 1

    peers = load_peers()

    # Always inject admin peer - prevents softlock if last.json is broken
    peers[config["vpn_admin_ip"]] = config["vpn_admin_public_key"]

    if not validate_peers(peers):
        return 1

    new_config = generate_config(config, peers)
    backup = backup_current_config()

    if not write_config(new_config):
        print("Error: failed to write config")
        return 1

    if not verify_config(str(WG_CONFIG_PATH)):
        print("Error: config verification failed, reverting")
        revert_config(backup)
        return 1

    if not reload_wireguard():
        print("Error: failed to reload WireGuard, reverting")
        revert_config(backup)
        reload_wireguard()
        return 1

    print(f"WireGuard config updated with {len(peers)} peers")
    return 0


if __name__ == "__main__":
    exit(main())
