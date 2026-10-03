#!/usr/bin/env python3
"""Osprey CLI — One-Command Plug-and-Play Supply Chain Attack Path Engine.

Usage:
  python cli.py scan [PATH]       Scan any project directory or repository
  python cli.py ui                Launch full dark-mode interactive web control plane
  python cli.py test              Run complete test suite (37 tests)
"""

import argparse
import os
import sys
import webbrowser
from pathlib import Path

# Add backend directory to PYTHONPATH
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def print_banner():
    banner = r"""
  ___  ____  ____  ____  ____  _  _ 
 / __)(  _ \/ ___)(  _ \(  __)( \/ )
( (__  ) __/\___ \ ) __/ ) _)  )  / 
 \___)(__)  (____/(__)  (____)(__/  v2.0
 [Osprey] Supply Chain Attack Path Control Plane
"""
    print(banner)


def run_scan(target_path_str: str):
    print_banner()
    from guardianos.inventory.scanner import scan_directory_manifests
    from guardianos.intel.service import intel_service
    from guardianos.attackpath.engine import construct_attack_paths

    target = Path(target_path_str).resolve()
    print(f">> Target Workspace: {target}")
    if not target.exists():
        print(f"Error: Path '{target}' does not exist.")
        sys.exit(1)

    print("\n[1/3] Scanning directory manifests (npm, pip, docker, etc.)...")
    try:
        result, manifests = scan_directory_manifests(target)
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

    print(f"  * Manifests Discovered: {len(manifests)}")
    for m in manifests:
        print(f"    - {m}")

    print(f"  * Normalized Components: {result.components_count}")
    print(f"  * Dependency Graph Edges: {result.relationships_count}")

    print("\n[2/3] Querying Google OSV.dev Live Advisory Feed...")
    findings = intel_service.scan_all_components()
    print(f"  * Advisories Identified: {len(findings)}")

    if findings:
        for f in findings[:5]:
            vuln_id = f.vulnerability_id
            pkg = f.component_name
            ver = f.installed_version
            fix = f.fixed_version or "Pending"
            sev = f.severity.value
            print(f"    [{sev}] {pkg}@{ver} -> {vuln_id} (Fix: {fix})")
        if len(findings) > 5:
            print(f"    ... and {len(findings) - 5} more advisories.")
    else:
        print("    [OK] Zero public vulnerabilities detected in target packages.")

    print("\n[3/3] Traversing Adversary Attack Paths & Computing Blast Radius...")
    paths = construct_attack_paths()
    open_paths = [p for p in paths if p.status.value == "OPEN"]
    print(f"  * Open Ingress-to-Cloud Attack Paths: {len(open_paths)}")

    if open_paths:
        for p in open_paths[:3]:
            print(f"    [ALERT] Path: {p.name}")
            print(f"            Condition: {p.exploitation_condition}")
            print(f"            Crown Jewel: {p.target_resource}")
            print(f"            Confidence: {int(p.confidence * 100)}%")
        if len(open_paths) > 3:
            print(f"    ... and {len(open_paths) - 3} more paths identified.")
    else:
        print("    [SECURE] Zero reachable paths from external ingress to sensitive cloud resources.")

    print("\n" + "=" * 65)
    print(">> To review visual kill-chain graph & approve 1-line Git PRs:")
    print("   Run: python cli.py ui")
    print("=" * 65 + "\n")


def run_ui():
    print_banner()
    print("🚀 Launching Osprey Control Plane...")
    import subprocess
    import time

    # Start FastAPI backend
    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "guardianos.api.app:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
        "--reload",
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(backend_dir)

    print("🔌 Starting Backend on http://127.0.0.1:8000 ...")
    backend_proc = subprocess.Popen(backend_cmd, cwd=str(root_dir), env=env)

    # Start Vite frontend
    frontend_dir = root_dir / "frontend"
    print("🎨 Starting Frontend on http://127.0.0.1:5173 ...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen([npm_cmd, "run", "dev", "--", "--host", "127.0.0.1"], cwd=str(frontend_dir))

    time.sleep(2)
    print("\n🌐 Opening browser to http://127.0.0.1:5173 ...")
    try:
        webbrowser.open("http://127.0.0.1:5173")
    except Exception:
        pass

    print("\n⚡ Osprey is running! Press Ctrl+C to stop.\n")
    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\n🛑 Stopping Osprey services...")
        backend_proc.terminate()
        frontend_proc.terminate()


def main():
    parser = argparse.ArgumentParser(description="Osprey — Supply Chain Attack Path Control Plane")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    scan_parser = subparsers.add_parser("scan", help="Scan local project manifests")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (default: current directory)")

    ui_parser = subparsers.add_parser("ui", help="Launch interactive web control plane")

    test_parser = subparsers.add_parser("test", help="Run test suite")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.path)
    elif args.command == "ui":
        run_ui()
    elif args.command == "test":
        import pytest
        sys.exit(pytest.main(["-c", "pytest.ini"]))
    else:
        # Default behavior: run scan on current directory
        run_scan(".")


if __name__ == "__main__":
    main()
