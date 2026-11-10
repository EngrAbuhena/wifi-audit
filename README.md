# Wi-Fi Audit

A non-intrusive Python CLI for reviewing the Wi-Fi security information reported by your operating system. It summarizes reported encryption, signal strength, and recommended configuration improvements for **networks you are authorized to assess**.

**Scope:** This utility reads OS-managed Wi-Fi information only. It does not capture packets, test passwords, attempt authentication, send attack frames, or exploit networks. The authorization flag is an acknowledgement, not a technical verification of permission.

## Requirements

- Python 3.9 or newer; no third-party Python packages
- A supported OS: Linux (NetworkManager's `nmcli`), Windows (`netsh`), or macOS (`networksetup`)
- A Wi-Fi adapter and permission to inspect the relevant networks

## Usage

From this repository's folder:

```bash
python wifi_audit.py --authorized I_HAVE_PERMISSION
```

Only use it where you have permission. Without that acknowledgement the program refuses to run.

Other examples:

```bash
# List OS-reported nearby networks and assess them (only where authorized)
python wifi_audit.py --authorized I_HAVE_PERMISSION --nearby

# Machine-readable output
python wifi_audit.py --authorized I_HAVE_PERMISSION --json

# Show full BSSIDs instead of masked identifiers
python wifi_audit.py --authorized I_HAVE_PERMISSION --show-identifiers

# See all flags
python wifi_audit.py --help
```

By default, findings target the active connection; on Linux, the network list may also display cached or nearby OS-reported entries. With `--nearby`, the tool assesses all networks returned by the OS. This is not a packet capture or an active vulnerability scan. On macOS, supported command-line tools provide the current SSID only, so nearby discovery and encryption classification may be unavailable. OS output and support vary by platform and locale; a reported security label is not proof of the router's configuration. In particular, an unknown security value should be confirmed on the router rather than treated as a verified open network.

**Privacy:** Reports include SSIDs and potentially location-revealing network details. BSSIDs are masked by default but `--show-identifiers` reveals them. Review reports before sharing them or committing them to Git.

## Tests

The automated tests use mocks and never require a Wi-Fi adapter or perform live discovery:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the same tests on pushes and pull requests.

## Upload to GitHub

Create an empty GitHub repository, then use **Add file → Upload files** to upload the **contents** of this folder (including `.github`), or push it using Git:

```bash
cd wifi-audit
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Replace the example remote URL with your repository URL. Git may require you to set your name/email and authenticate before pushing.

No license is included; choose one before inviting reuse or contributions.
