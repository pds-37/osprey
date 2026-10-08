"""Parser adversarial probes run out of process to contain native failures."""

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
_ANALYZE = (
    "import json,sys; from osprey.analyzers.source import analyze_source_files; "
    "files=json.load(sys.stdin); result=analyze_source_files(files,['axios']); "
    "print(json.dumps({'errors':result.errors,'files':result.files_scanned,"
    "'usages':len(result.usages),'calls':len(result.call_edges)}))"
)


def _analyze_in_subprocess(files: dict[str, str]) -> dict:
    env = os.environ.copy()
    package_paths = [str(ROOT / "osprey" / "src"), str(ROOT / "backend")]
    env["PYTHONPATH"] = os.pathsep.join([*package_paths, env.get("PYTHONPATH", "")])
    completed = subprocess.run(
        [sys.executable, "-c", _ANALYZE],
        cwd=ROOT,
        env=env,
        input=json.dumps(files),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout)


def test_malformed_and_recovered_syntax_is_reported_without_native_failure():
    fixtures = {
        "truncated.js": "import x from 'axios'; function (",
        "malformed.ts": "export { from 'axios';",
        "malformed.tsx": "export default function App( { return <div>",
        "malformed.go": 'package p\nimport "fmt"\nfunc main( { fmt.Println("x")',
        "malformed.py": "import axios\ndef broken(:\n    pass\n",
        "unicode.js": "const snowman = '\u2603\ufe0f'; // import axios\n",
        "nul.js": "const source = 'left\\x00right'; // import axios\n",
    }
    for path, source in fixtures.items():
        result = _analyze_in_subprocess({path: source})
        if path.endswith((".js", ".ts", ".tsx", ".go", ".py")) and "malformed" in path or path.startswith("truncated"):
            assert result["errors"], path
        if path.startswith(("unicode", "nul")):
            assert result["files"] == [path]


def test_pathological_javascript_returns_ast_limit_instead_of_unbounded_walk():
    source = "const values = [" + ",".join("0" for _ in range(100_000)) + "];"
    result = _analyze_in_subprocess({"generated.js": source})

    assert any("4096-node safety limit" in error for error in result["errors"])
    assert result["usages"] == 0
    assert result["calls"] == 0


def test_pathological_go_returns_ast_limit_instead_of_unbounded_walk():
    source = 'package main\nimport "fmt"\nfunc main() {\n' + "\n".join(
        f"fmt.Println({index})" for index in range(2_000)
    ) + "\n}"
    result = _analyze_in_subprocess({"generated.go": source})

    assert any("Go AST exceeded the 4096-node safety limit" in error for error in result["errors"])
    assert result["usages"] == 0
    assert result["calls"] == 0


def test_unpaired_surrogate_is_rejected_before_evidence_hashing():
    source = json.loads('"\\udcff"')
    result = _analyze_in_subprocess({"invalid-unicode.js": source})

    assert result["files"] == []
    assert any("invalid Unicode" in error for error in result["errors"])
