# LinuxSecMonitor

LinuxSecMonitor is a defensive Linux security monitoring project. Sprint 1 collects basic host information and an installed package inventory. It does **not** identify vulnerabilities or claim complete security coverage.

## Sprint 1 features

- Read-only system information from Python's `platform` module and Linux `/etc/os-release`.
- Debian/Ubuntu package names and versions from `dpkg-query`.
- Human-readable output or structured JSON on standard output / in a file.
- Graceful scan errors with a distinct successful empty inventory.

The package scanner supports Debian and Ubuntu only. It invokes `dpkg-query` with an argument list (no shell) and performs no package modifications or privileged actions.

## Setup and usage

Python 3.10 or newer is recommended. From the project directory:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
python main.py --json
python main.py --json --output scan.json
```

Package inventory requires Debian or Ubuntu and the `dpkg-query` command. System information remains available on other operating systems, but the package scan reports that it is unsupported.

## Tests

```bash
python -m pytest
```

Tests mock operating-system metadata and package-manager calls, so they can run on Windows without `dpkg-query`.

## Project layout

```text
scanner/       system information and package inventory modules
tests/         pytest coverage for collectors and CLI
main.py        command-line interface
```
