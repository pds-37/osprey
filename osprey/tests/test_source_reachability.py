from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import analyze_source_files
from osprey.core.evidence import EvidenceStore
from osprey.core.models import EvidenceType, ReachabilityStatus


def test_python_route_to_advisory_mapped_symbol_is_reachable():
    code = '''
from vulnerable_pkg import decode_image

@router.post("/upload")
def upload():
    return process()

def process():
    return decode_image()
'''
    store = EvidenceStore()
    analysis = analyze_source_files({"app.py": code}, ["vulnerable-pkg"], store)
    result = analyze_reachability(
        analysis,
        package="vulnerable-pkg",
        vulnerable_symbols=["decode_image"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert "POST /upload (app.py:4)" in result.path
    assert result.explanation == result.reason
    assert result.limitations
    assert result.evidence
    assert all(store.get(evidence_id) for evidence_id in result.evidence)


def test_javascript_route_and_alias_reachability():
    code = '''
import { decode as parse } from "vulnerable-pkg";
function handler(req, res) {
  return parse(req.body);
}
app.post("/upload", handler);
'''
    analysis = analyze_source_files({"src/app.js": code}, ["vulnerable-pkg"])
    result = analyze_reachability(
        analysis,
        package="vulnerable-pkg",
        vulnerable_symbols=["decode"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "vulnerable-pkg.decode"


def test_typescript_arrow_handler_reaches_namespace_import_symbol():
    code = '''
import * as lodash from "lodash";
const processTemplate = (value: string) => lodash.template(value);
const handler = async (req: Request) => processTemplate(req.body);
router.post("/render", handler);
'''
    analysis = analyze_source_files({"src/app.ts": code}, ["lodash"])
    result = analyze_reachability(analysis, package="lodash", vulnerable_symbols=["lodash.template"])
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "lodash.template"
    assert "POST /render (src/app.ts:5)" in result.path


def test_commonjs_require_and_function_alias_are_resolved():
    code = '''
const { template: render } = require("lodash");
function handler(req) { return render(req.body); }
app.post("/render", handler);
'''
    analysis = analyze_source_files({"app.js": code}, ["lodash"])
    result = analyze_reachability(analysis, package="lodash", vulnerable_symbols=["template"])
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "lodash.template"


def test_dynamic_import_without_static_flow_is_unknown():
    code = '''
async function handler(req) {
  const loaded = await import(req.query.module);
  return loaded.decode(req.body);
}
app.post("/decode", handler);
'''
    analysis = analyze_source_files({"app.js": code}, ["vulnerable-pkg"])
    result = analyze_reachability(analysis, package="vulnerable-pkg", vulnerable_symbols=["decode"])
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("dynamic import flow is not resolved" in error for error in analysis.errors)


def test_vulnerable_symbol_outside_observed_route_is_unknown():
    code = '''
from vulnerable_pkg import decode
@router.post("/health")
def health(): return "ok"
def background_job(): return decode(payload)
'''
    analysis = analyze_source_files({"app.py": code}, ["vulnerable_pkg"])
    result = analyze_reachability(analysis, package="vulnerable_pkg", vulnerable_symbols=["decode"])
    assert result.status == ReachabilityStatus.UNKNOWN
    assert "no supported path" in result.reason


def test_go_route_to_imported_vulnerable_symbol_is_reachable():
    code = '''
package main
import (
    "net/http"
    "example.com/codec"
)
func handler(w http.ResponseWriter, r *http.Request) { decode(r.Body) }
func decode(body io.Reader) { codec.Decode(body) }
func main() { http.HandleFunc("/upload", handler) }
'''
    analysis = analyze_source_files({"main.go": code}, ["example.com/codec"])
    result = analyze_reachability(analysis, package="example.com/codec", vulnerable_symbols=["Decode"])
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "example.com/codec.Decode"
    assert "HTTP /upload (main.go:9)" in result.path


def test_unrelated_package_symbol_is_not_reachable_from_observed_route():
    code = '''
import lodash from "lodash";
function handler(req, res) {
  return lodash.debounce(work, 10);
}
app.get("/", handler);
'''
    analysis = analyze_source_files({"app.js": code}, ["lodash"])
    result = analyze_reachability(analysis, package="lodash", vulnerable_symbols=["template"])
    assert result.status == ReachabilityStatus.NOT_REACHABLE
    assert result.limitations
    assert result.evidence


def test_package_advisory_without_vulnerable_symbol_is_unknown():
    analysis = analyze_source_files({"app.py": "def main():\n    return 1\n"}, ["example"])
    result = analyze_reachability(analysis, package="example", vulnerable_symbols=[])
    assert result.status == ReachabilityStatus.UNKNOWN
    assert result.limitations


def test_python_parse_failure_is_unknown():
    analysis = analyze_source_files({"broken.py": "def handler(:\n    pass"}, ["example"])
    result = analyze_reachability(analysis, package="example", vulnerable_symbols=["unsafe"])
    assert result.status == ReachabilityStatus.UNKNOWN


def test_evidence_ids_are_content_addressed_and_typed():
    store = EvidenceStore()
    first = store.add(evidence_type=EvidenceType.MANIFEST, source="test", location="requirements.txt", content="x==1")
    second = store.add(evidence_type=EvidenceType.MANIFEST, source="test", location="requirements.txt", content="x==1")
    assert first.id == second.id
    assert len(first.content_hash) == 64


def _reachability(code: str, filename: str, package: str, symbols: list[str]):
    analysis = analyze_source_files({filename: code}, [package])
    return analysis, analyze_reachability(analysis, package=package, vulnerable_symbols=symbols)


def test_javascript_named_import_direct_call_is_reachable_with_explanation():
    analysis, result = _reachability(
        'import { template } from "lodash";\n'
        'function handler(req) { return template(req.body); }\n'
        'app.post("/render", handler);\n',
        "src/app.js", "lodash", ["template"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "lodash.template"
    assert result.confidence > 0
    assert "template" in result.explanation
    assert result.limitations
    assert not analysis.errors


def test_javascript_vulnerable_import_without_call_is_not_reachable():
    _, result = _reachability(
        'import { template } from "lodash";\n'
        'function handler() { return "ok"; }\n'
        'app.get("/health", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert result.status == ReachabilityStatus.NOT_REACHABLE
    assert "no supported call" in result.explanation
    assert result.evidence


def test_top_level_javascript_dependency_call_is_not_misreported_not_reachable():
    analysis, result = _reachability(
        'import { template } from "lodash";\n'
        'template(startup_value);\n'
        'function handler() { return "ok"; }\n'
        'app.get("/health", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert any(usage.usage_type == "CALL" and usage.caller is None for usage in analysis.usages)
    assert result.status == ReachabilityStatus.UNKNOWN
    assert "no supported path" in result.explanation


def test_javascript_safe_symbol_from_vulnerable_package_is_not_reachable():
    _, result = _reachability(
        'const lodash = require("lodash");\n'
        'function handler() { return lodash.debounce(work, 10); }\n'
        'app.post("/run", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert result.status == ReachabilityStatus.NOT_REACHABLE
    assert result.path == ()


def test_javascript_parameter_shadowing_does_not_become_dependency_reachable():
    analysis, result = _reachability(
        'import { template } from "lodash";\n'
        'function handler(template) { return template(input); }\n'
        'app.post("/render", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert not any(usage.usage_type == "CALL" for usage in analysis.usages)
    assert result.status == ReachabilityStatus.NOT_REACHABLE


def test_javascript_commonjs_namespace_and_destructured_alias_calls_are_reachable():
    namespace, namespace_result = _reachability(
        'const lodash = require("lodash");\n'
        'function handler() { return lodash.template(input); }\n'
        'app.post("/render", handler);\n',
        "app.js", "lodash", ["lodash.template"],
    )
    destructured, destructured_result = _reachability(
        'const { template: render } = require("lodash");\n'
        'function handler() { return render(input); }\n'
        'app.post("/render", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert namespace_result.status == ReachabilityStatus.REACHABLE
    assert namespace_result.path[-1] == "lodash.template"
    assert destructured_result.status == ReachabilityStatus.REACHABLE
    assert destructured_result.path[-1] == "lodash.template"
    assert not namespace.errors
    assert not destructured.errors


def test_javascript_namespace_import_and_import_alias_are_reachable():
    namespace, namespace_result = _reachability(
        'import * as lib from "codec";\n'
        'function handler() { return lib.decode(input); }\n'
        'app.post("/decode", handler);\n',
        "app.js", "codec", ["decode"],
    )
    aliased, alias_result = _reachability(
        'import { decode as dangerous } from "codec";\n'
        'function handler() { return dangerous(input); }\n'
        'app.post("/decode", handler);\n',
        "app.ts", "codec", ["decode"],
    )
    assert namespace_result.status == ReachabilityStatus.REACHABLE
    assert alias_result.status == ReachabilityStatus.REACHABLE
    assert namespace_result.path[-1] == alias_result.path[-1] == "codec.decode"
    assert not namespace.errors
    assert not aliased.errors


def test_typescript_subpath_symbol_keeps_its_module_qualification():
    analysis, result = _reachability(
        'import { decode as parse } from "codec/transforms";\n'
        'const handler = (req: Request) => parse(req.body);\n'
        'app.post("/decode", handler);\n',
        "src/app.ts", "codec", ["transforms.decode"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "codec.transforms.decode"
    assert not analysis.errors


def test_computed_javascript_dependency_access_is_unknown():
    analysis, result = _reachability(
        'import * as lodash from "lodash";\n'
        'function handler(req) { return lodash[req.query.fn](req.body); }\n'
        'app.post("/render", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("computed dependency access" in error for error in analysis.errors)
    assert "incomplete" in result.explanation.lower()
    assert result.limitations


def test_dynamic_commonjs_require_is_unknown():
    analysis, result = _reachability(
        'function handler(req) { const lib = require(req.query.package); return lib.template(); }\n'
        'app.post("/render", handler);\n',
        "app.js", "lodash", ["template"],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("dynamic require" in error for error in analysis.errors)


def test_package_reexport_is_recorded_but_cross_file_use_stays_unknown():
    analysis = analyze_source_files(
        {
            "src/reexport.ts": 'export { template as render } from "lodash";\n',
            "src/app.ts": 'import { render } from "./reexport";\n'
            'function handler() { return render(input); }\n'
            'app.post("/render", handler);\n',
        },
        ["lodash"],
    )
    result = analyze_reachability(
        analysis, package="lodash", vulnerable_symbols=["template"]
    )
    assert any(usage.usage_type == "IMPORT" and usage.symbol == "template" for usage in analysis.usages)
    assert result.status == ReachabilityStatus.UNKNOWN
    assert result.limitations


def test_python_vulnerable_import_without_call_is_not_reachable():
    _, result = _reachability(
        'from vulnerable_pkg import decode\n'
        '@app.get("/health")\n'
        'def health():\n    return "ok"\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert result.status == ReachabilityStatus.NOT_REACHABLE
    assert result.evidence


def test_top_level_python_dependency_call_is_not_misreported_not_reachable():
    analysis, result = _reachability(
        'from vulnerable_pkg import decode\n'
        'decode(startup_value)\n'
        '@app.get("/health")\n'
        'def health():\n    return "ok"\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert any(usage.usage_type == "CALL" and usage.caller is None for usage in analysis.usages)
    assert result.status == ReachabilityStatus.UNKNOWN
    assert "no supported path" in result.explanation


def test_python_module_alias_and_submodule_symbol_are_reachable():
    analysis, result = _reachability(
        'import vulnerable_pkg.transforms as transforms\n'
        '@app.post("/decode")\n'
        'def handler():\n    return transforms.decode(payload)\n',
        "app.py", "vulnerable-pkg", ["transforms.decode"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert result.path[-1] == "vulnerable-pkg.transforms.decode"
    assert not analysis.errors


def test_python_from_import_alias_and_safe_symbol_are_distinguished():
    aliased, alias_result = _reachability(
        'from vulnerable_pkg.transforms import decode as dangerous\n'
        '@app.post("/decode")\n'
        'def handler():\n    return dangerous(payload)\n',
        "app.py", "vulnerable-pkg", ["transforms.decode"],
    )
    safe, safe_result = _reachability(
        'from vulnerable_pkg import safe_function\n'
        '@app.post("/safe")\n'
        'def handler():\n    return safe_function(payload)\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert alias_result.status == ReachabilityStatus.REACHABLE
    assert alias_result.path[-1] == "vulnerable-pkg.transforms.decode"
    assert safe_result.status == ReachabilityStatus.NOT_REACHABLE
    assert "safe_function" not in safe_result.path
    assert not aliased.errors
    assert not safe.errors


def test_python_parameter_shadowing_does_not_become_dependency_reachable():
    analysis, result = _reachability(
        'from vulnerable_pkg import decode\n'
        '@app.post("/decode")\n'
        'def handler(decode):\n    return decode(payload)\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert not any(usage.usage_type == "CALL" for usage in analysis.usages)
    assert result.status == ReachabilityStatus.NOT_REACHABLE


def test_python_reflective_dependency_access_is_unknown():
    analysis, result = _reachability(
        'import vulnerable_pkg as package\n'
        '@app.post("/decode")\n'
        'def handler():\n    return getattr(package, symbol)(payload)\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("reflective dependency calls" in error for error in analysis.errors)
    assert result.limitations


def test_python_dynamic_import_is_unknown():
    analysis, result = _reachability(
        'from importlib import import_module\n'
        '@app.post("/decode")\n'
        'def handler():\n    package = import_module(module_name)\n    return package.decode(payload)\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("importlib module flow" in error for error in analysis.errors)


def test_python_local_function_alias_is_unknown_instead_of_a_negative_result():
    analysis, result = _reachability(
        'import vulnerable_pkg as package\n'
        '@app.post("/decode")\n'
        'def handler():\n'
        '    decode = package.decode\n'
        '    return decode(payload)\n',
        "app.py", "vulnerable-pkg", ["decode"],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert any("function aliases are not resolved" in error for error in analysis.errors)
