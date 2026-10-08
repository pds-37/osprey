# Contributing to Osprey

Thank you for contributing to Osprey! Osprey is an open-source, deterministic software supply chain vulnerability triage CLI built with Python 3.10+.

---

## Core Guardrails & Principles

When contributing to Osprey, please respect these strict design guardrails:
1. **Read-Only Parsing**: Never execute, install, or import code from scanned target repositories. Parse manifests purely as plain text or structured formats (JSON, TOML, YAML).
2. **Minimal Dependencies & Speed**: Osprey must scan repositories in seconds. Do not add heavy dependencies or background database daemons.
3. **Deterministic Output**: For a given manifest tree and vulnerability feed cache, Osprey must yield reproducible risk tiering without stochastic scoring.
4. **Honest Confidence**: Exposure inference is strictly package-level, clearly marked as `declared`, `inferred`, or `unknown`. Do not claim function-level reachability.
5. **No Telemetry**: No phone-home telemetry, no user tracking, and no required API keys.

---

## Local Development Setup

### 1. Clone & Set Up Virtual Environment

```bash
cd osprey
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

pip install -e .
pip install pytest ruff
```

### 2. Running Linting and Tests

```bash
# Lint checks with Ruff
python -m ruff check src tests

# Run offline unit test suite
python -m pytest -v
```

*Note: All unit tests must pass completely offline with no live internet access.*

---

## How to Add a Parser in One File

Adding support for a new package manager or ecosystem (e.g., Go `go.mod`, Rust `Cargo.lock`, Ruby `Gemfile.lock`, Maven `pom.xml`) can be completed in a single file under `src/osprey/parsers/`.

### Step 1: Understand the `Parser` Protocol

All manifest parsers implement the `Parser` protocol defined in `src/osprey/parsers/base.py`:

```python
from pathlib import Path
from typing import List, Protocol
from osprey.models import Component

class Parser(Protocol):
    def detect(self, path: Path) -> bool:
        """Return True if this parser handles the given file path."""
        ...

    def parse(self, path: Path) -> List[Component]:
        """Safely parse file as plain text and extract components."""
        ...
```

### Step 2: Create `src/osprey/parsers/<ecosystem>.py`

Create a new parser file implementing `detect` and `parse`. Here is an annotated blueprint:

```python
"""Parser for Go modules (go.mod)."""

from __future__ import annotations
from pathlib import Path
from typing import List
from osprey.models import Component
from osprey.parsers.base import make_purl

class GoModParser:
    """Parses go.mod dependencies into Component models."""

    def detect(self, path: Path) -> bool:
        # Fast filename check; do not open file here
        return path.name == "go.mod"

    def parse(self, path: Path) -> List[Component]:
        components: List[Component] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return components

        # Parse text lines safely (never run `go list` or shell commands)
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue

            if in_require or line.startswith("require "):
                parts = line.removeprefix("require ").split()
                if len(parts) >= 2:
                    mod_path = parts[0]
                    version = parts[1].lstrip("v")
                    is_indirect = "// indirect" in line

                    components.append(
                        Component(
                            name=mod_path,
                            version=version,
                            ecosystem="Go",
                            purl=make_purl("golang", mod_path, version),
                            is_dev=is_indirect,  # Or classify dev/indirect dependencies
                            source_file=str(path),
                        )
                    )
        return components
```

### Key Requirements for Parsers:
- **`make_purl(type, name, version)`**: Generate standard Package URLs according to [PURL specifications](https://github.com/package-url/purl-spec).
- **`is_dev` Flag**: Mark development/test dependencies as `is_dev=True` so risk tiering can accurately apply the `dev-only` exposure rule.
- **`source_file`**: Store `str(path)` on each `Component` so exposure inference can attribute the component to the owning service.
- **Fail Gracefully**: If the file contains syntax errors or unexpected formatting, return what could be parsed or an empty list without crashing.

### Step 3: Register the Parser in `src/osprey/scanner.py`

Import your new parser and add it to `DEFAULT_PARSERS` in `src/osprey/scanner.py`:

```python
from osprey.parsers.golang import GoModParser

DEFAULT_PARSERS: List[Parser] = [
    NpmPackageParser(),
    NpmLockParser(),
    PyPiRequirementsParser(),
    PyProjectTomlParser(),
    GoModParser(),          # <-- Add your parser here
    DockerfileParser(),
    ComposeParser(),
]
```

### Step 4: Add Unit Tests in `tests/test_parsers.py`

Add a test function in `tests/test_parsers.py` using a mock or `tmp_path` fixture:

```python
def test_go_mod_parser(tmp_path: Path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n",
        encoding="utf-8",
    )
    parser = GoModParser()
    assert parser.detect(go_mod) is True
    comps = parser.parse(go_mod)
    assert len(comps) == 1
    assert comps[0].name == "github.com/gin-gonic/gin"
    assert comps[0].version == "1.9.1"
    assert comps[0].ecosystem == "Go"
```

---

## Submitting Pull Requests

1. Keep PRs focused on a single feature, parser, or bug fix.
2. Ensure full test coverage: run `pytest -v` and `ruff check .`.
3. Update `CHANGELOG.md` with your changes.
