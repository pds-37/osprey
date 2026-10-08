# Clean Virtual Environment Installation & Smoke Test Check

This document outlines the procedure to verify a clean-room installation of the Osprey CLI distribution package (`osprey-sc`).

---

## 1. Prerequisites
- Python 3.10, 3.11, or 3.12+
- `pip` and `venv` module

---

## 2. Build Wheel Distribution

From the root of the `./osprey/` repository:

```bash
# 1. Ensure build tooling is installed
python -m pip install --upgrade pip build

# 2. Build the sdist and wheel
python -m build
```

Verify that the `.whl` and `.tar.gz` artifacts are created in the `./dist/` directory:
- `dist/osprey_sc-0.1.0-py3-none-any.whl`
- `dist/osprey_sc-0.1.0.tar.gz`

---

## 3. Clean Virtual Environment Installation

Create an isolated virtual environment completely separate from your development dependencies:

### On Linux / macOS:
```bash
python -m venv /tmp/osprey-smoke-env
source /tmp/osprey-smoke-env/bin/activate
pip install dist/osprey_sc-0.1.0-py3-none-any.whl
```

### On Windows (PowerShell):
```powershell
python -m venv "$env:TEMP\osprey-smoke-env"
& "$env:TEMP\osprey-smoke-env\Scripts\Activate.ps1"
pip install (Get-Item dist\osprey_sc-*.whl).FullName
```

Alternatively, test using `pipx`:
```bash
pipx install dist/osprey_sc-0.1.0-py3-none-any.whl --force
```

---

## 4. Verification & Smoke Checks

Execute the following smoke tests against the installed `osprey` executable:

### Check 1: CLI Version and Help
```bash
osprey --version
# Expected Output: Osprey v0.1.0
# Exit code: 0

osprey --help
# Expected: Displays commands (scan, explain, init, demo)
# Exit code: 0
```

### Check 2: Offline Demo Execution
Point to the bundled fixture cache to run the demo fully offline:

```bash
# Linux / macOS
export OSPREY_CACHE_DIR="$(pwd)/tests/fixtures/cache"
osprey demo --offline

# Windows (PowerShell)
$env:OSPREY_CACHE_DIR = (Resolve-Path "tests/fixtures/cache").Path
osprey demo --offline
```

**Expected Result**:
- Exit code: `0`
- Output shows:
  ```text
  Scanning bundled vulnerable sample application...
  Osprey scan: .../examples/vulnerable-app
  20 findings -> 8 need action
  ACT NOW (2)
  PLAN (6)
  ```

### Check 3: Deterministic Finding Audit
Verify that `explain` provides full line-item attribution:
```bash
osprey explain GHSA-35jh-r3h4-6jhm --path examples/vulnerable-app --offline
```
**Expected Result**:
- Exit code: `0`
- Displays evidence chain with firing risk rule, package-level exposure, and minimal safe version `fix: >= 4.17.21`.

### Check 4: Policy-Driven Exit Codes
```bash
# Fail on ACT NOW vulnerabilities
osprey scan examples/vulnerable-app --offline --fail-on act-now
# Exit code: 1

# Nonexistent target folder error handling (no stack traces)
osprey scan invalid-dir-path
# Exit code: 2
```

---

## 5. Cleanup

```bash
# Linux / macOS
deactivate
rm -rf /tmp/osprey-smoke-env

# Windows (PowerShell)
deactivate
Remove-Item -Recurse -Force "$env:TEMP\osprey-smoke-env"
```
