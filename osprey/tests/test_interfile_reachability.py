from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import analyze_source_files
from osprey.core.models import ReachabilityStatus


PACKAGE = "vulnerable-pkg"
SYMBOL = "decode"


def _scan(files, *, max_graph_depth=64):
    analysis = analyze_source_files(
        files,
        [PACKAGE],
        max_graph_depth=max_graph_depth,
    )
    result = analyze_reachability(
        analysis,
        package=PACKAGE,
        vulnerable_symbols=[SYMBOL],
    )
    return analysis, result


def test_reaches_vulnerable_symbol_through_one_local_js_module():
    analysis, result = _scan({
        "app.ts": '''
import { parse } from "./parser";
import { decode } from "vulnerable-pkg";
function handler(req: Request) { return parse(req.body); }
app.post("/upload", handler);
''',
        "parser.ts": '''
import { decode } from "vulnerable-pkg";
export function parse(input: Uint8Array) { return decode(input); }
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert any(edge.source_file == "app.ts" and edge.target_file == "parser.ts" for edge in analysis.call_edges)
    assert any("parser.ts:" in step and "parse()" in step for step in result.path)


def test_reaches_vulnerable_symbol_through_two_local_js_modules():
    _, result = _scan({
        "routes.ts": '''
import { processUpload } from "./services/upload";
app.post("/upload", processUpload);
''',
        "services/upload.ts": '''
import { parseDocument } from "../documents/parser";
export function processUpload(req: Request) { return parseDocument(req.body); }
''',
        "documents/parser.ts": '''
import { decode } from "vulnerable-pkg";
export function parseDocument(data: Uint8Array) { return decode(data); }
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert any("services/upload.ts:" in step and "processUpload()" in step for step in result.path)
    assert any("documents/parser.ts:" in step and "parseDocument()" in step for step in result.path)


def test_reaches_vulnerable_symbol_through_multiple_modules_and_index_resolution():
    _, result = _scan({
        "routes.tsx": '''
import { uploadHandler } from "./services";
app.post("/upload", uploadHandler);
''',
        "services/index.ts": '''
import { processDocument } from "../documents/document";
export function uploadHandler(req: Request) { return processDocument(req.body); }
''',
        "documents/document.ts": '''
import { parse } from "../parser";
export function processDocument(data: Uint8Array) { return parse(data); }
''',
        "parser/index.ts": '''
import { decode } from "vulnerable-pkg";
export function parse(data: Uint8Array) { return decode(data); }
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert len({step.split(":", 1)[0] for step in result.path if ".ts" in step}) >= 3
    assert any("parser/index.ts:" in step for step in result.path)


def test_vulnerable_package_import_without_vulnerable_call_is_not_reachable():
    _, result = _scan({
        "app.js": '''
import { decode } from "vulnerable-pkg";
function handler() { return 1; }
app.get("/", handler);
''',
    })

    assert result.status is ReachabilityStatus.NOT_REACHABLE


def test_safe_function_from_vulnerable_package_is_not_reachable():
    _, result = _scan({
        "app.js": '''
import { safe } from "vulnerable-pkg";
function handler() { return safe(); }
app.get("/", handler);
''',
    })

    assert result.status is ReachabilityStatus.NOT_REACHABLE


def test_same_name_in_an_unimported_file_does_not_create_a_synthetic_edge():
    analysis, result = _scan({
        "app.ts": '''
function helper() { return 1; }
function handler() { return helper(); }
app.get("/", handler);
''',
        "other.ts": '''
import { decode } from "vulnerable-pkg";
export function helper() { return decode(); }
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert not any(edge.target_file == "other.ts" for edge in analysis.call_edges)


def test_named_import_alias_resolves_across_files():
    analysis, result = _scan({
        "app.ts": '''
import { processData as process } from "./service";
function handler() { return process(); }
app.post("/", handler);
''',
        "service.ts": '''
import { decode } from "vulnerable-pkg";
export function processData() { return decode(); }
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert any(edge.source_symbol == "handler" and edge.target_symbol == "processData" for edge in analysis.call_edges)


def test_commonjs_destructured_require_resolves_across_files():
    _, result = _scan({
        "app.js": '''
const { processData } = require("./service");
function handler() { return processData(); }
app.post("/", handler);
''',
        "service.js": '''
const { decode } = require("vulnerable-pkg");
function processData() { return decode(); }
module.exports = { processData };
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE


def test_commonjs_namespace_require_resolves_across_files():
    _, result = _scan({
        "app.js": '''
const service = require("./service.js");
function handler() { return service.processData(); }
app.post("/", handler);
''',
        "service.js": '''
const { decode } = require("vulnerable-pkg");
function processData() { return decode(); }
module.exports = { processData };
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE


def test_python_from_import_resolves_across_workspace_modules():
    _, result = _scan({
        "routes.py": '''
from services.parser import parse_document
@router.post("/upload")
def upload_handler():
    return parse_document(b"data")
''',
        "services/__init__.py": "",
        "services/parser.py": '''
from vulnerable_pkg import decode
def parse_document(data):
    return decode(data)
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert any("services/parser.py:" in step and "parse_document()" in step for step in result.path)


def test_python_module_import_resolves_across_workspace_modules():
    _, result = _scan({
        "routes.py": '''
import services.parser
@router.post("/upload")
def upload_handler():
    return services.parser.parse_document(b"data")
''',
        "services/__init__.py": "",
        "services/parser.py": '''
from vulnerable_pkg import decode
def parse_document(data):
    return decode(data)
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE


def test_python_relative_import_resolves_with_package_markers():
    _, result = _scan({
        "app/__init__.py": "",
        "app/routes.py": '''
from .parser import parse_document
@router.post("/upload")
def upload_handler():
    return parse_document(b"data")
''',
        "app/parser.py": '''
from vulnerable_pkg import decode
def parse_document(data):
    return decode(data)
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE


def test_python_method_call_edges_keep_class_scope():
    analysis, result = _scan({
        "routes.py": '''
from vulnerable_pkg import decode
class UploadRoutes:
    @router.post("/upload")
    def upload_handler(self):
        return self.parse_document()
    def parse_document(self):
        return decode(b"data")
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert any(edge.source_symbol == "upload_handler" and edge.target_symbol == "parse_document" for edge in analysis.call_edges)


def test_parameter_shadowing_does_not_follow_imported_function_across_files():
    analysis, result = _scan({
        "app.ts": '''
import { process } from "./service";
function handler(process: () => number) { return process(); }
app.get("/", handler);
''',
        "service.ts": '''
import { decode } from "vulnerable-pkg";
export function process() { return decode(); }
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert not any(edge.source_file == "app.ts" and edge.target_file == "service.ts" for edge in analysis.call_edges)


def test_circular_imports_terminate_and_keep_supported_path():
    analysis, result = _scan({
        "routes.py": '''
from services.process import process
@router.post("/upload")
def upload_handler():
    return process()
def helper():
    return process()
''',
        "services/__init__.py": "",
        "services/process.py": '''
from routes import helper
from vulnerable_pkg import decode
def process():
    helper()
    return decode()
''',
    })

    assert result.status is ReachabilityStatus.REACHABLE
    assert analysis.call_graph
    assert any(edge.source_file == "services/process.py" and edge.target_file == "routes.py" for edge in analysis.call_edges)


def test_unresolved_relative_import_returns_unknown_with_limitation():
    analysis, result = _scan({
        "app.ts": '''
import { process } from "./missing";
function handler() { return process(); }
app.post("/", handler);
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("could not be resolved" in error for error in analysis.errors)


def test_ambiguous_relative_module_candidates_are_not_guessed():
    analysis, result = _scan({
        "app.ts": '''
import { process } from "./service";
function handler() { return process(); }
app.post("/", handler);
''',
        "service.js": "export function process() { return 1; }\n",
        "service.ts": "export function process() { return 2; }\n",
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("is ambiguous" in error for error in analysis.errors)


def test_dynamic_import_remains_unknown():
    analysis, result = _scan({
        "app.ts": '''
async function handler(name: string) {
    const module = await import(name);
    return module.decode();
}
app.get("/", handler);
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("dynamic import" in error for error in analysis.errors)


def test_syntax_recovery_remains_unknown_with_explicit_limitation():
    analysis, result = _scan({
        "app.tsx": '''
import { decode } from "vulnerable-pkg";
function handler() { return decode( ; }
app.get("/", handler);
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("syntax recovery" in error for error in analysis.errors)


def test_oversized_tsx_tree_is_skipped_with_unknown_limitation():
    calls = ", ".join("transform(item)" for _ in range(1500))
    analysis, result = _scan({
        "app.tsx": (
            'import { decode } from "vulnerable-pkg";\n'
            f"function handler() {{ return [{calls}]; }}\n"
            'app.post("/upload", handler);\n'
        ),
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("4096-node safety limit" in error for error in analysis.errors)
    assert not result.path


def test_unresolved_route_handler_is_limited_and_unknown():
    analysis, result = _scan({
        "app.ts": '''
import { decode } from "vulnerable-pkg";
app.post("/upload", missingHandler);
''',
    })

    assert result.status is ReachabilityStatus.UNKNOWN
    assert any("route handler" in error for error in analysis.errors)


def test_traversal_limit_is_explicit_and_returns_unknown():
    analysis, result = _scan({
        "app.ts": '''
import { first } from "./first";
function handler() { return first(); }
app.post("/", handler);
''',
        "first.ts": '''
import { second } from "./second";
export function first() { return second(); }
''',
        "second.ts": '''
import { decode } from "vulnerable-pkg";
export function second() { return decode(); }
''',
    }, max_graph_depth=1)

    assert result.status is ReachabilityStatus.UNKNOWN
    assert analysis.traversal_truncated
    assert any("truncated" in item.lower() for item in result.limitations)
