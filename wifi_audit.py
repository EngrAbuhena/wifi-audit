#!/usr/bin/env python3
"""Wi-Fi security posture auditor for authorized networks.

This utility only collects configuration and OS-managed radio information. It
never captures packets, sends deauthentication frames, attempts authentication,
or tests passwords.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

APP_NAME = "Wi-Fi Audit"
AUTH_ACK = "I_HAVE_PERMISSION"


@dataclass
class Network:
    ssid: str = "<hidden>"
    bssid: Optional[str] = None
    security: str = "Unknown"
    signal: Optional[int] = None
    channel: Optional[str] = None
    frequency: Optional[str] = None
    active: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    recommendation: str


def run(command: list[str], timeout: int = 15) -> str:
    """Run a local OS utility without invoking a shell."""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return ""
    return completed.stdout or ""


def clean(value: str) -> str:
    return value.strip() if value and value.strip() else "<hidden>"


def mask_identifier(identifier: Optional[str]) -> Optional[str]:
    if not identifier:
        return None
    parts = re.split(r"[:-]", identifier)
    if len(parts) == 6:
        return ":".join(parts[:3] + ["xx", "xx", "xx"])
    return identifier[:4] + "…" if len(identifier) > 4 else identifier


def linux_networks(nearby: bool) -> list[Network]:
    if not shutil.which("nmcli"):
        return []
    fields = "ACTIVE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"
    command = ["nmcli", "-t", "--escape", "yes", "-f", fields, "device", "wifi", "list"]
    if nearby:
        command += ["--rescan", "auto"]
    raw = run(command)
    networks: list[Network] = []
    for line in raw.splitlines():
        # nmcli --escape uses backslashes, so split only on unescaped colons.
        values = re.split(r"(?<!\\):", line)
        values = [v.replace("\\:", ":").replace("\\\\", "\\") for v in values]
        if len(values) < 7:
            continue
        active, ssid, bssid, channel, frequency, signal, security = values[:7]
        try:
            strength = int(signal) if signal else None
        except ValueError:
            strength = None
        networks.append(Network(
            ssid=clean(ssid), bssid=bssid or None, security=security or "Open",
            signal=strength, channel=channel or None, frequency=frequency or None,
            active=active.lower() == "yes",
        ))
    return networks


def windows_networks(nearby: bool) -> list[Network]:
    if not shutil.which("netsh"):
        return []
    if not nearby:
        raw = run(["netsh", "wlan", "show", "interfaces"])
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        if not fields or fields.get("state", "").lower() != "connected":
            return []
        signal = re.search(r"(\d+)", fields.get("signal", ""))
        return [Network(
            ssid=clean(fields.get("ssid", "")), bssid=fields.get("bssid"),
            security=fields.get("authentication", "Unknown"),
            signal=int(signal.group(1)) if signal else None,
            channel=fields.get("channel"), active=True,
        )]

    raw = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks: list[Network] = []
    ssid, auth, encrypt = "<hidden>", "Unknown", ""
    current: Optional[Network] = None
    for line in raw.splitlines():
        stripped = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", stripped, flags=re.I)
        if m:
            ssid = clean(m.group(1))
            continue
        if ":" not in stripped:
            continue
        key, value = [x.strip() for x in stripped.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "authentication":
            auth = value
        elif key_lower == "encryption":
            encrypt = value
        elif key_lower == "bssid":
            current = Network(ssid=ssid, bssid=value, security=f"{auth} / {encrypt}".strip(" /"))
            networks.append(current)
        elif current and key_lower == "signal":
            m_signal = re.search(r"(\d+)", value)
            current.signal = int(m_signal.group(1)) if m_signal else None
        elif current and key_lower == "channel":
            current.channel = value
    return networks


def macos_networks(nearby: bool) -> list[Network]:
    # macOS removed its supported command-line scanner. We intentionally do not
    # call private frameworks or force radio scans; report only the active SSID.
    raw = run(["/usr/sbin/networksetup", "-getairportnetwork", "en0"])
    m = re.search(r":\s*(.*)$", raw.strip())
    if not m or "not associated" in raw.lower():
        return []
    note = "Nearby discovery is unavailable with supported macOS CLI tools."
    return [Network(ssid=clean(m.group(1)), active=True, notes=[note])]


def get_networks(nearby: bool) -> tuple[list[Network], str]:
    system = platform.system()
    if system == "Linux":
        if not shutil.which("nmcli"):
            return [], "nmcli was not found. Install NetworkManager or run on a supported OS."
        return linux_networks(nearby), ""
    if system == "Windows":
        return windows_networks(nearby), ""
    if system == "Darwin":
        return macos_networks(nearby), ""
    return [], f"{system} is not supported. Supported platforms: Linux, Windows, macOS."


def assess(networks: list[Network], nearby: bool) -> list[Finding]:
    findings: list[Finding] = []
    targets = networks if nearby else [n for n in networks if n.active]
    if not targets:
        findings.append(Finding(
            "INFO", "No active Wi-Fi connection detected",
            "The operating system did not report a connected Wi-Fi network.",
            "Connect to an authorized network and rerun the audit.",
        ))
        return findings

    for network in targets:
        label = f"“{network.ssid}”"
        sec = network.security.lower().replace(" ", "")
        if not network.security or network.security.lower() in {"open", "none", "--", "unknown"}:
            findings.append(Finding("HIGH", f"Open network: {label}",
                "No Wi-Fi link-layer encryption was reported.",
                "Use WPA3-Personal where available, or WPA2-AES as a minimum."))
        elif "wep" in sec:
            findings.append(Finding("CRITICAL", f"Legacy WEP detected: {label}",
                "WEP is obsolete and does not provide adequate protection.",
                "Replace WEP immediately with WPA3-Personal or WPA2-AES."))
        elif "wpa" in sec and "wpa2" not in sec and "wpa3" not in sec:
            findings.append(Finding("HIGH", f"Legacy WPA detected: {label}",
                "Original WPA is deprecated and vulnerable to known weaknesses.",
                "Set the access point to WPA3-Personal or WPA2-AES only."))
        elif "wpa2" in sec and "wpa3" not in sec:
            findings.append(Finding("MEDIUM", f"WPA2-only network: {label}",
                "WPA2-AES is broadly acceptable, but WPA3 offers stronger modern protection.",
                "Enable WPA3-Personal if every client supports it; disable TKIP and WPS."))
        elif "wpa3" in sec:
            findings.append(Finding("INFO", f"Modern encryption reported: {label}",
                "WPA3 was reported by the operating system.",
                "Keep router firmware current and use a unique, long passphrase."))
        else:
            findings.append(Finding("INFO", f"Encryption could not be classified: {label}",
                f"Reported security: {network.security}.",
                "Confirm the router uses WPA2-AES or WPA3 and that WPS is disabled."))

        if network.signal is not None and network.signal < 35:
            findings.append(Finding("LOW", f"Weak signal: {label}",
                f"Reported signal is {network.signal}%.",
                "Improve access-point placement or coverage; avoid solving this by lowering security settings."))
    return findings


def serialize_network(network: Network, show_identifiers: bool) -> dict[str, Any]:
    value = asdict(network)
    if not show_identifiers:
        value["bssid"] = mask_identifier(network.bssid)
    return value


def report_text(networks: list[Network], findings: list[Finding], nearby: bool, show_identifiers: bool, notice: str) -> str:
    lines = [
        f"{APP_NAME} — authorized, non-intrusive posture report",
        f"Generated: {datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}",
        f"Mode: {'OS-managed nearby listing' if nearby else 'current connection'}",
        "",
    ]
    if notice:
        lines.extend([f"NOTE: {notice}", ""])
    lines.append("NETWORKS")
    if not networks:
        lines.append("  No Wi-Fi networks were returned by the operating system.")
    for network in networks:
        bssid = network.bssid if show_identifiers else mask_identifier(network.bssid)
        fields = [f"SSID={network.ssid}", f"security={network.security}"]
        if network.active:
            fields.append("active=yes")
        if bssid:
            fields.append(f"BSSID={bssid}")
        if network.signal is not None:
            fields.append(f"signal={network.signal}%")
        if network.channel:
            fields.append(f"channel={network.channel}")
        lines.append("  - " + " | ".join(fields))
        lines.extend(f"    note: {note}" for note in network.notes)

    lines.extend(["", "FINDINGS"])
    for finding in findings:
        lines.append(f"  [{finding.severity}] {finding.title}")
        lines.append(f"    {finding.detail}")
        lines.append(f"    Recommendation: {finding.recommendation}")
    lines.extend([
        "",
        "SCOPE",
        "  This tool does not capture traffic, transmit attack frames, probe devices,",
        "  attempt passwords, exploit access points, or bypass authentication.",
    ])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized, non-intrusive Wi-Fi configuration posture auditor."
    )
    parser.add_argument("--authorized", metavar="ACK", help=f"Required acknowledgement: {AUTH_ACK}")
    parser.add_argument("--nearby", action="store_true", help="List networks reported by the operating system Wi-Fi manager.")
    parser.add_argument("--json", action="store_true", help="Emit a JSON report.")
    parser.add_argument("--show-identifiers", action="store_true", help="Show full BSSIDs instead of masking them in output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.authorized != AUTH_ACK:
        print(
            "Refusing to run without an authorization acknowledgement.\n"
            f"Use --authorized {AUTH_ACK} only for networks and locations you are permitted to assess.",
            file=sys.stderr,
        )
        return 2

    networks, notice = get_networks(args.nearby)
    findings = assess(networks, args.nearby)
    if args.json:
        payload = {
            "tool": APP_NAME,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "nearby" if args.nearby else "current_connection",
            "notice": notice or None,
            "networks": [serialize_network(n, args.show_identifiers) for n in networks],
            "findings": [asdict(f) for f in findings],
            "scope": "Configuration and OS-managed Wi-Fi information only; no traffic capture, attacks, password attempts, or exploitation.",
        }
        print(json.dumps(payload, indent=2))
    else:
        print(report_text(networks, findings, args.nearby, args.show_identifiers, notice))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
