"""Conservative static extraction of routes, imports, functions, and calls.

Python is parsed with the standard-library AST; JavaScript, TypeScript/TSX, and Go use
Tree-sitter grammars. This is syntax-level evidence, not a complete semantic call graph.
Unsupported constructs and parser recovery are reported as analysis errors. Source files
are never imported, executed, or modified.
"""

from __future__ import annotations

import ast
import posixpath
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any, Iterator

try:
    import tree_sitter_go
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Node, Parser
except ImportError:  # pragma: no cover - handled as an explicit analysis limitation below
    tree_sitter_go = tree_sitter_javascript = tree_sitter_typescript = None
    Language = Node = Parser = Any

from osprey.core.evidence import EvidenceStore
from osprey import __version__
from osprey.core.models import (
    DependencyUsage,
    EvidenceType,
    ExposureObservation,
)

MAX_JS_AST_NODES = 4096
MAX_GO_AST_NODES = 4096


@dataclass
class SourceAnalysis:
    exposures: list[ExposureObservation] = field(default_factory=list)
    usages: list[DependencyUsage] = field(default_factory=list)
    call_graph: dict[str, list[str]] = field(default_factory=dict)
    functions: dict[str, "FunctionRecord"] = field(default_factory=dict)
    module_imports: list["ModuleImport"] = field(default_factory=list)
    call_sites: list["CallSite"] = field(default_factory=list)
    call_edges: list["CallEdge"] = field(default_factory=list)
    exports: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    route_handler_refs: list["RouteHandlerRef"] = field(default_factory=list)
    route_parents: dict[str, str | None] = field(default_factory=dict)
    route_origins: dict[str, str] = field(default_factory=dict)
    route_parent_edges: dict[str, "CallEdge"] = field(default_factory=dict)
    route_depths: dict[str, int] = field(default_factory=dict)
    traversal_truncated: bool = False
    function_evidence: dict[str, str] = field(default_factory=dict)
    file_evidence: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    max_graph_depth: int = 64


@dataclass(frozen=True)
class FunctionRecord:
    id: str
    file: str
    name: str
    line: int
    language: str
    evidence_id: str
    scope: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        name = ".".join((*self.scope, self.name))
        return f"{self.file}:{self.line} {name}()"


@dataclass(frozen=True)
class ModuleImport:
    file: str
    specifier: str
    local_name: str
    imported_name: str
    mode: str
    line: int
    language: str
    level: int = 0


@dataclass(frozen=True)
class CallSite:
    file: str
    caller_id: str
    callee: str
    line: int
    language: str
    shadowed: bool = False


@dataclass(frozen=True)
class CallEdge:
    source_file: str
    source_symbol: str
    target_file: str
    target_symbol: str
    line: int
    resolution: str
    confidence: float
    source_id: str
    target_id: str


@dataclass(frozen=True)
class RouteHandlerRef:
    exposure_index: int
    local_name: str
    file: str
    line: int


# Parser instances can be short-lived, but their compiled Language objects must
# stay alive while any tree or node created from the grammar is being traversed.
_TREE_SITTER_LANGUAGES: dict[str, Any] = {}


def _canonical_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _package_root(import_name: str, language: str) -> str:
    value = import_name.strip()
    if language in {"javascript", "typescript"}:
        if value.startswith("@"):
            parts = value.split("/")
            return "/".join(parts[:2]) if len(parts) > 1 else value
        return value.split("/", 1)[0]
    if language == "python":
        return value.split(".", 1)[0]
    return value


def _package_match(imported: str, dependency: str, language: str) -> bool:
    left = _canonical_package(_package_root(imported, language))
    right = _canonical_package(dependency)
    return left == right or (language == "go" and (imported == dependency or imported.startswith(dependency.rstrip("/") + "/")))


def _module_subpath(imported: str, dependency: str, language: str) -> str:
    """Return an explicit module path below a matched package, when present."""
    if not _package_match(imported, dependency, language):
        return ""
    if language == "javascript" or language == "typescript":
        root = _package_root(imported, language)
        return imported[len(root):].lstrip("/") if imported.startswith(root) else ""
    if language == "python":
        root = _package_root(imported, language)
        if _canonical_package(root) == _canonical_package(dependency):
            return imported[len(root):].lstrip(".")
    return ""


def _record_file(path: str, text: str, store: EvidenceStore) -> str:
    return store.add(
        evidence_type=EvidenceType.SOURCE_FILE,
        source="workspace source scanner",
        location=path,
        content=text,
        metadata={
            "bytes": len(text.encode("utf-8", "replace")),
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_type": "source_file",
        },
    ).id


def _record_line(
    store: EvidenceStore,
    evidence_type: EvidenceType,
    path: str,
    line: int,
    line_text: str,
    confidence: float,
    **metadata: Any,
) -> str:
    return store.add(
        evidence_type=evidence_type,
        source="static source analysis",
        location=f"{path}:{line}",
        content=line_text,
        confidence=confidence,
        metadata={
            **metadata,
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_type": "static_source",
        },
    ).id


def _python_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str, str, int] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        func = decorator.func
        if not isinstance(func, ast.Attribute) or func.attr.lower() not in {
            "route", "get", "post", "put", "delete", "patch", "options", "head"
        }:
            continue
        route = decorator.args[0].value if decorator.args and isinstance(decorator.args[0], ast.Constant) else None
        if not isinstance(route, str):
            continue
        method = func.attr.upper()
        if func.attr.lower() == "route":
            methods_kw = next((kw.value for kw in decorator.keywords if kw.arg == "methods"), None)
            if isinstance(methods_kw, (ast.List, ast.Tuple)):
                methods = [item.value.upper() for item in methods_kw.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                method = ",".join(methods) if methods else "UNKNOWN"
            else:
                method = "GET"
        framework = "FastAPI/Starlette" if func.attr.lower() in {"get", "post", "put", "delete", "patch", "options", "head"} else "Flask/Django-style"
        route_line = min((item.lineno for item in node.decorator_list), default=node.lineno)
        return framework, method, route, route_line
    return None


def _attribute_chain(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attribute_chain(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _analyze_python(path: str, text: str, deps: list[str], store: EvidenceStore, result: SourceAnalysis) -> None:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        result.errors.append(f"{path}:{exc.lineno or 1}: Python syntax could not be parsed")
        return

    # alias -> (module path, imported symbol, binding mode)
    # Modes retain Python's distinction between `import pkg.sub`, its aliased
    # form, and `from pkg.sub import symbol` so module qualification is not lost.
    imports: dict[str, tuple[str, str, str]] = {}
    ambiguous_imports: set[str] = set()

    def bind_python_import(alias: str, binding: tuple[str, str, str], line: int) -> None:
        existing = imports.get(alias)
        if existing is not None and existing != binding:
            ambiguous_imports.add(alias)
            result.errors.append(f"{path}:{line}: dependency binding {alias!r} has multiple meanings")
            return
        imports[alias] = binding

    function_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_nodes.append(node)
        elif isinstance(node, ast.Import):
            for item in node.names:
                bound = item.asname or item.name.split(".", 1)[0]
                mode = "module_alias" if item.asname else "module_root"
                bind_python_import(bound, (item.name, "", mode), node.lineno)
                result.module_imports.append(
                    ModuleImport(path, item.name, bound, "", mode, node.lineno, "python")
                )
                line_text = text.splitlines()[node.lineno - 1] if node.lineno <= len(text.splitlines()) else ""
                evidence_id = _record_line(store, EvidenceType.IMPORT, path, node.lineno, line_text, 0.95, package=item.name)
                for dep in deps:
                    if _package_match(item.name, dep, "python"):
                        result.usages.append(DependencyUsage(dep, path, node.lineno, "", "IMPORT", 0.95, evidence_id=evidence_id))
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            for item in node.names:
                if item.name == "*":
                    result.errors.append(f"{path}:{node.lineno}: wildcard imports cannot be resolved")
                    continue
                bound = item.asname or item.name
                bind_python_import(bound, (module_name, item.name, "from"), node.lineno)
                result.module_imports.append(
                    ModuleImport(path, module_name, bound, item.name, "from", node.lineno, "python", node.level)
                )
                line_text = text.splitlines()[node.lineno - 1] if node.lineno <= len(text.splitlines()) else ""
                for dep in deps:
                    if module_name and _package_match(module_name, dep, "python"):
                        imported_symbol = ".".join(part for part in (_module_subpath(module_name, dep, "python"), item.name) if part)
                        evidence_id = _record_line(store, EvidenceType.IMPORT, path, node.lineno, line_text, 0.95, package=dep, symbol=imported_symbol)
                        result.usages.append(DependencyUsage(dep, path, node.lineno, imported_symbol, "IMPORT", 0.95, evidence_id=evidence_id))

    class ModuleRebindings(ast.NodeVisitor):
        def mark_target(self, target: ast.AST) -> None:
            chain = _attribute_chain(target)
            if chain:
                alias = chain.split(".", 1)[0]
                if alias in imports:
                    ambiguous_imports.add(alias)
                    result.errors.append(f"{path}:{getattr(target, 'lineno', 1)}: modified dependency binding is not resolved")

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node.name in imports:
                ambiguous_imports.add(node.name)
                result.errors.append(f"{path}:{node.lineno}: dependency binding is shadowed by a function definition")

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)  # function bodies have their own local scope

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if node.name in imports:
                ambiguous_imports.add(node.name)
                result.errors.append(f"{path}:{node.lineno}: dependency binding is shadowed by a class definition")
            for child in node.body:
                self.visit(child)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Store) and node.id in imports:
                ambiguous_imports.add(node.id)
                result.errors.append(f"{path}:{node.lineno}: reassigned dependency binding is not resolved")

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                if isinstance(target, (ast.Attribute, ast.Subscript)):
                    self.mark_target(target)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, (ast.Attribute, ast.Subscript)):
                self.mark_target(node.target)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            if isinstance(node.target, (ast.Attribute, ast.Subscript)):
                self.mark_target(node.target)
            self.generic_visit(node)

    rebindings = ModuleRebindings()
    rebindings.visit(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            result.errors.append(f"{path}:{node.lineno}: dynamic Python import flow is not resolved")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
            result.errors.append(f"{path}:{node.lineno}: importlib module flow is not resolved")
        elif isinstance(node.func, ast.Name) and node.func.id in imports:
            imported_module, imported_symbol, _binding_mode = imports[node.func.id]
            if imported_module == "importlib" and imported_symbol == "import_module":
                result.errors.append(f"{path}:{node.lineno}: importlib module flow is not resolved")
        elif isinstance(node.func, ast.Name) and node.func.id == "setattr" and node.args:
            target = node.args[0]
            if isinstance(target, ast.Name) and target.id in imports:
                ambiguous_imports.add(target.id)
                result.errors.append(f"{path}:{node.lineno}: reflective dependency mutation is not resolved")
        elif isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args:
            target = node.args[0]
            if isinstance(target, ast.Name) and target.id in imports:
                result.errors.append(f"{path}:{node.lineno}: reflective dependency calls are not resolved")
        if isinstance(node.func, ast.Subscript):
            base = _attribute_chain(node.func.value)
            if base and base.split(".", 1)[0] in imports:
                result.errors.append(f"{path}:{node.lineno}: computed dependency access is not resolved")

    # A stored function value imported from a dependency is not followed through
    # local assignments. Keep the finding unknown instead of missing the call.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            value = node.value
        else:
            continue
        chain = _attribute_chain(value) if value is not None else None
        if chain and chain.split(".", 1)[0] in imports:
            result.errors.append(f"{path}:{node.lineno}: dependency function aliases are not resolved")

    parent_nodes = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    def function_scope(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
        scope: list[str] = []
        parent = parent_nodes.get(node)
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope.append(parent.name)
            parent = parent_nodes.get(parent)
        return tuple(reversed(scope))

    qualified_names = {id(node): ".".join((*function_scope(node), node.name)) for node in function_nodes}
    qualified_counts: dict[str, int] = {}
    names_to_ids: dict[str, list[str]] = {}
    function_ids_by_node: dict[int, str] = {}
    for node in function_nodes:
        qualified = qualified_names[id(node)]
        qualified_counts[qualified] = qualified_counts.get(qualified, 0) + 1
    for node in function_nodes:
        name = node.name
        qualified = qualified_names[id(node)]
        suffix = f"@{node.lineno}" if qualified_counts[qualified] > 1 else ""
        function_id = f"{path}::{qualified}{suffix}"
        function_ids_by_node[id(node)] = function_id
        names_to_ids.setdefault(name, []).append(function_id)
        line_text = text.splitlines()[node.lineno - 1] if node.lineno <= len(text.splitlines()) else ""
        evidence_id = _record_line(store, EvidenceType.FUNCTION, path, node.lineno, line_text, 0.98, function=name)
        result.function_evidence[function_id] = evidence_id
        result.call_graph.setdefault(function_id, [])
        result.functions[function_id] = FunctionRecord(
            function_id, path, name, node.lineno, "python", evidence_id, function_scope(node)
        )
        if node in tree.body:
            result.exports.setdefault(path, {}).setdefault(name, []).append(function_id)

    class FunctionCalls(ast.NodeVisitor):
        def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.root = root
            self.calls: list[ast.Call] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is self.root:
                for child in node.body:
                    self.visit(child)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is self.root:
                for child in node.body:
                    self.visit(child)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            if node is self.root:
                self.visit(node.body)

        def visit_Call(self, node: ast.Call) -> None:
            self.calls.append(node)
            self.generic_visit(node)

    class ModuleCalls(ast.NodeVisitor):
        def __init__(self) -> None:
            self.calls: list[ast.Call] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            self.calls.append(node)
            self.generic_visit(node)

    def record_dependency_call(
        call: ast.Call,
        caller_id: str | None,
        shadowed: set[str] | None = None,
    ) -> None:
        chain = _attribute_chain(call.func)
        if not chain:
            return
        parts = chain.split(".")
        if parts[0] not in imports or parts[0] in ambiguous_imports or parts[0] in (shadowed or set()):
            return
        module, imported_symbol, binding_mode = imports[parts[0]]
        for dep in deps:
            if not _package_match(module, dep, "python"):
                continue
            module_prefix = _module_subpath(module, dep, "python")
            if binding_mode == "module_root":
                symbol_parts = parts[1:]
            elif binding_mode == "module_alias":
                symbol_parts = ([module_prefix] if module_prefix else []) + parts[1:]
            else:
                symbol_parts = ([module_prefix] if module_prefix else []) + [imported_symbol] + parts[1:]
            symbol = ".".join(part for part in symbol_parts if part)
            line_text = text.splitlines()[call.lineno - 1] if call.lineno <= len(text.splitlines()) else ""
            evidence_id = _record_line(
                store, EvidenceType.IMPORT, path, call.lineno, line_text, 0.95,
                package=dep, symbol=symbol, caller=caller_id,
            )
            result.usages.append(DependencyUsage(dep, path, call.lineno, symbol, "CALL", 0.95, caller_id, evidence_id))

    module_visitor = ModuleCalls()
    module_visitor.visit(tree)
    for call in module_visitor.calls:
        record_dependency_call(call, None)

    class LocalBindings(ast.NodeVisitor):
        def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.root = root
            self.names = {
                arg.arg
                for arg in (
                    *root.args.posonlyargs,
                    *root.args.args,
                    *root.args.kwonlyargs,
                )
            }
            if root.args.vararg:
                self.names.add(root.args.vararg.arg)
            if root.args.kwarg:
                self.names.add(root.args.kwarg.arg)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is self.root:
                for child in node.body:
                    self.visit(child)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is self.root:
                for child in node.body:
                    self.visit(child)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Store):
                self.names.add(node.id)

    for node in function_nodes:
        name = node.name
        caller_id = function_ids_by_node[id(node)]
        local_bindings = LocalBindings(node)
        local_bindings.visit(node)
        shadowed = local_bindings.names & set(imports)
        local_calls: set[str] = set()
        call_visitor = FunctionCalls(node)
        call_visitor.visit(node)
        for child in call_visitor.calls:
            chain = _attribute_chain(child.func)
            if not chain:
                continue
            parts = chain.split(".")
            result.call_sites.append(CallSite(
                path, caller_id, chain, child.lineno, "python",
                parts[0] in shadowed or parts[0] in ambiguous_imports,
            ))
            if parts[0] in imports:
                record_dependency_call(child, caller_id, shadowed)
                continue

            target_id: str | None = None
            caller_scope = function_scope(node)
            if len(parts) == 1:
                candidates = names_to_ids.get(parts[0], [])
                same_scope = [
                    candidate for candidate in candidates
                    if result.functions[candidate].scope == caller_scope
                ]
                nested_scope = [
                    candidate for candidate in candidates
                    if result.functions[candidate].scope == (*caller_scope, node.name)
                ]
                globals_ = [candidate for candidate in candidates if not result.functions[candidate].scope]
                eligible = same_scope or nested_scope or globals_
                if len(eligible) == 1:
                    target_id = eligible[0]
                elif len(eligible) > 1:
                    result.errors.append(f"{path}:{child.lineno}: local call target {parts[0]!r} is ambiguous")
            elif len(parts) == 2 and parts[0] in {"self", "cls"} and caller_scope:
                candidates = [
                    candidate for candidate in names_to_ids.get(parts[1], [])
                    if result.functions[candidate].scope == caller_scope
                ]
                if len(candidates) == 1:
                    target_id = candidates[0]
                elif len(candidates) > 1:
                    result.errors.append(f"{path}:{child.lineno}: method call target {chain!r} is ambiguous")
            if target_id and target_id != caller_id:
                local_calls.add(target_id)
                target = result.functions[target_id]
                source_function = result.functions[caller_id]
                result.call_edges.append(CallEdge(
                    source_function.file, source_function.name, target.file, target.name,
                    child.lineno, "same-file static call", 0.95, caller_id, target_id,
                ))
        result.call_graph[caller_id] = sorted(local_calls)

        route = _python_route(node)
        if route:
            framework, method, route_path, route_line = route
            line_text = text.splitlines()[route_line - 1] if route_line <= len(text.splitlines()) else ""
            evidence_id = _record_line(store, EvidenceType.ROUTE, path, route_line, line_text, 0.9, method=method, route=route_path, handler=name)
            result.exposures.append(ExposureObservation(framework, method, route_path, path, route_line, 0.9, caller_id, evidence_id))


def _ts_walk(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _ts_walk_with_parents(root: Node, *, max_nodes: int) -> tuple[list[Node], dict[int, Node], bool]:
    """Walk once and retain parent links without creating parent Node wrappers."""
    nodes: list[Node] = []
    parents: dict[int, Node] = {}
    pending: list[tuple[Node, Node | None]] = [(root, None)]
    while pending:
        node, parent = pending.pop()
        nodes.append(node)
        if len(nodes) > max_nodes:
            return nodes, parents, False
        if parent is not None:
            parents[node.id] = parent
        pending.extend((child, node) for child in reversed(node.named_children))
    return nodes, parents, True


def _ts_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _ts_field(node: Node, field: str, source: bytes) -> str:
    return _ts_text(node.child_by_field_name(field), source)


def _ts_static_string(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type not in {
        "string", "template_string", "interpreted_string_literal", "raw_string_literal"
    }:
        return None
    raw = _ts_text(node, source)
    if node.type == "template_string" and "${" in raw:
        return None
    if raw.startswith(("'", '"', "`")) and raw[-1:] == raw[:1]:
        return raw[1:-1]
    return None


def _ts_identifier(node: Node | None, source: bytes) -> str:
    if node is None or node.type not in {"identifier", "property_identifier", "field_identifier"}:
        return ""
    return _ts_text(node, source)


def _ts_root_identifier(node: Node | None, source: bytes) -> str:
    """Find the static base identifier of member/computed access syntax."""
    if node is None:
        return ""
    current = node
    for _ in range(64):
        if current.type == "identifier":
            return _ts_identifier(current, source)
        if current.type == "member_expression":
            children = current.named_children
            if len(children) != 2 or children[1].type != "property_identifier":
                return ""
            candidate = children[0]
        elif current.type in {"subscript_expression", "optional_subscript_expression"}:
            children = current.named_children
            candidate = children[0] if children else None
        else:
            return ""
        if candidate is None or candidate.type not in {"identifier", "member_expression", "subscript_expression", "optional_subscript_expression"}:
            return ""
        current = candidate
        if current is None:
            return ""
    return ""


def _ts_member_chain(node: Node | None, source: bytes) -> str:
    """Return a dotted chain only when every member is statically named."""
    if node is None:
        return ""
    parts: list[str] = []
    current = node
    for _ in range(64):
        if current.type == "identifier":
            base = _ts_identifier(current, source)
            return ".".join(reversed([*parts, base])) if base else ""
        if current.type != "member_expression":
            return ""
        children = current.named_children
        if len(children) != 2 or children[1].type != "property_identifier":
            return ""
        object_node, property_node = children[0], children[-1]
        property_name = _ts_identifier(property_node, source)
        if not property_name or object_node is None or object_node.type not in {"identifier", "member_expression"}:
            return ""
        parts.append(property_name)
        current = object_node
    return ""


def _ts_line_text(lines: list[str], line: int) -> str:
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _ts_parser(language: str) -> Parser | None:
    if Parser is Any or Language is Any:
        return None
    if language not in _TREE_SITTER_LANGUAGES:
        if language == "javascript":
            grammar = tree_sitter_javascript.language()
        elif language == "typescript":
            grammar = tree_sitter_typescript.language_typescript()
        elif language == "tsx":
            grammar = tree_sitter_typescript.language_tsx()
        elif language == "go":
            grammar = tree_sitter_go.language()
        else:
            return None
        _TREE_SITTER_LANGUAGES[language] = Language(grammar)
    return Parser(_TREE_SITTER_LANGUAGES[language])


def _add_import_usage(
    package: str,
    path: str,
    line: int,
    language: str,
    deps: list[str],
    store: EvidenceStore,
    result: SourceAnalysis,
    line_text: str,
    *,
    symbol: str = "",
    confidence: float = 0.9,
) -> None:
    for dep in deps:
        if _package_match(package, dep, language):
            evidence_id = _record_line(
                store,
                EvidenceType.IMPORT,
                path,
                line,
                line_text,
                confidence,
                package=dep,
                **({"symbol": symbol} if symbol else {}),
            )
            result.usages.append(DependencyUsage(dep, path, line, symbol, "IMPORT", confidence, evidence_id=evidence_id))


def _analyze_js(path: str, text: str, language: str, deps: list[str], store: EvidenceStore, result: SourceAnalysis) -> None:
    parser = _ts_parser(language)
    if parser is None:
        result.errors.append(f"{path}: Tree-sitter parser dependencies are unavailable")
        return
    source = text.encode("utf-8", "replace")
    tree = parser.parse(source)
    if tree is None:
        result.errors.append(f"{path}: JavaScript/TypeScript parser timed out")
        return
    root = tree.root_node
    if root.has_error:
        # Recovery nodes have triggered a native Tree-sitter access violation
        # during deeper TSX traversal on Windows. Do not inspect a recovered
        # tree: mark this file incomplete so reachability remains UNKNOWN.
        result.errors.append(
            f"{path}: JavaScript/TypeScript syntax recovery was required; AST analysis was skipped for stability"
        )
        return
    nodes, parents, complete = _ts_walk_with_parents(root, max_nodes=MAX_JS_AST_NODES)
    if not complete:
        result.errors.append(
            f"{path}: AST exceeded the {MAX_JS_AST_NODES}-node safety limit; analysis was skipped for stability"
        )
        return
    lines = text.splitlines()
    function_kinds = {"function_declaration", "generator_function_declaration", "method_definition", "arrow_function", "function_expression"}

    def is_module_scope(node: Node) -> bool:
        ancestor = parents.get(node.id)
        while ancestor is not None and ancestor.id != root.id:
            if ancestor.type in function_kinds or ancestor.type in {"class_declaration", "class"}:
                return False
            ancestor = parents.get(ancestor.id)
        return True
    # alias -> (package specifier, imported symbol); package subpaths are retained
    # in the specifier and restored when recording a symbol use.
    bindings: dict[str, tuple[str, str]] = {}
    ambiguous_bindings: set[str] = set()

    def bind_import(alias: str, package: str, symbol: str) -> None:
        value = (package, symbol)
        existing = bindings.get(alias)
        if existing is not None and existing != value:
            ambiguous_bindings.add(alias)
            result.errors.append(f"{path}: dependency binding {alias!r} has multiple meanings")
            return
        bindings[alias] = value

    for node in nodes:
        if node.type == "import_statement":
            pkg = _ts_static_string(node.child_by_field_name("source"), source)
            if not pkg:
                result.errors.append(f"{path}:{node.start_point.row + 1}: non-static import source was not resolved")
                continue
            if _ts_text(node, source).lstrip().startswith("import type "):
                continue
            clause = next((child for child in node.named_children if child.type == "import_clause"), None)
            line = node.start_point.row + 1
            if clause:
                for item in clause.named_children:
                    if item.type == "identifier":
                        alias = _ts_text(item, source)
                        bind_import(alias, pkg, "")
                        if pkg.startswith("."):
                            result.module_imports.append(ModuleImport(path, pkg, alias, "default", "default", line, language))
                    elif item.type == "namespace_import":
                        alias_node = item.named_children[-1] if item.named_children else None
                        alias = _ts_identifier(alias_node, source)
                        if alias:
                            bind_import(alias, pkg, "")
                            if pkg.startswith("."):
                                result.module_imports.append(ModuleImport(path, pkg, alias, "", "namespace", line, language))
                    elif item.type == "named_imports":
                        for specifier in item.named_children:
                            if specifier.type != "import_specifier":
                                continue
                            imported_node = specifier.child_by_field_name("name") or (specifier.named_children[0] if specifier.named_children else None)
                            alias_node = specifier.child_by_field_name("alias")
                            imported = _ts_identifier(imported_node, source)
                            alias = _ts_identifier(alias_node, source) or imported
                            if alias:
                                bind_import(alias, pkg, imported)
                                if pkg.startswith("."):
                                    result.module_imports.append(ModuleImport(path, pkg, alias, imported, "named", line, language))
            _add_import_usage(pkg, path, line, language, deps, store, result, _ts_line_text(lines, line))

        elif node.type == "export_statement":
            pkg = _ts_static_string(node.child_by_field_name("source"), source)
            if not pkg:
                continue
            line = node.start_point.row + 1
            if pkg.startswith("."):
                result.errors.append(f"{path}:{line}: local re-export calls across files are not resolved")
            export_clause = next((child for child in node.named_children if child.type == "export_clause"), None)
            specifiers = [child for child in export_clause.named_children if child.type == "export_specifier"] if export_clause else []
            if not specifiers:
                _add_import_usage(pkg, path, line, language, deps, store, result, _ts_line_text(lines, line))
                result.errors.append(f"{path}:{line}: wildcard or empty package re-export is not resolved")
                continue
            for specifier in specifiers:
                exported_node = specifier.child_by_field_name("name") or (specifier.named_children[0] if specifier.named_children else None)
                exported = _ts_identifier(exported_node, source)
                for dep in deps:
                    if not exported or not _package_match(pkg, dep, language):
                        continue
                    module_prefix = _module_subpath(pkg, dep, language)
                    symbol = ".".join(part for part in (module_prefix, exported) if part)
                    evidence_id = _record_line(
                        store, EvidenceType.IMPORT, path, line, _ts_line_text(lines, line), 0.9,
                        package=dep, symbol=symbol, reexport=True,
                    )
                    result.usages.append(DependencyUsage(dep, path, line, symbol, "IMPORT", 0.9, evidence_id=evidence_id))
            result.errors.append(f"{path}:{line}: package re-exports may be used by unresolved cross-file callers")

    # CommonJS requires are statically supported only when the module path is a
    # string literal and the binding is a simple identifier or object pattern.
    for node in nodes:
        if node.type != "call_expression":
            continue
        if not is_module_scope(node):
            callee = node.child_by_field_name("function")
            if callee and callee.type == "import":
                result.errors.append(f"{path}: function-scoped dynamic import flow is not resolved")
            elif callee and callee.type == "identifier" and _ts_identifier(callee, source) == "require":
                result.errors.append(f"{path}: function-scoped dynamic require flow is not resolved")
            continue
        callee_text = _ts_field(node, "function", source)
        if callee_text == "import":
            result.errors.append(f"{path}:{node.start_point.row + 1}: dynamic import flow is not resolved")
            continue
        if callee_text != "require":
            continue
        arguments = node.child_by_field_name("arguments")
        first = arguments.named_children[0] if arguments and arguments.named_children else None
        pkg = _ts_static_string(first, source)
        if not pkg:
            result.errors.append(f"{path}:{node.start_point.row + 1}: dynamic require could not be resolved")
            continue
        parent = parents.get(node.id)
        name_node = parent.child_by_field_name("name") if parent and parent.type == "variable_declarator" else None
        if name_node and name_node.type == "identifier":
            alias = _ts_text(name_node, source)
            bind_import(alias, pkg, "")
            if pkg.startswith("."):
                result.module_imports.append(ModuleImport(path, pkg, alias, "", "namespace", node.start_point.row + 1, language))
        elif name_node and name_node.type == "object_pattern":
            for child in name_node.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    symbol = _ts_text(child, source)
                    bind_import(symbol, pkg, symbol)
                    if pkg.startswith("."):
                        result.module_imports.append(ModuleImport(path, pkg, symbol, symbol, "named", node.start_point.row + 1, language))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    value = child.child_by_field_name("value")
                    symbol, alias = _ts_text(key, source), _ts_identifier(value, source)
                    if alias:
                        bind_import(alias, pkg, symbol)
                        if pkg.startswith("."):
                            result.module_imports.append(ModuleImport(path, pkg, alias, symbol, "named", node.start_point.row + 1, language))
        else:
            result.errors.append(f"{path}:{node.start_point.row + 1}: require result binding could not be resolved")
        line = node.start_point.row + 1
        _add_import_usage(pkg, path, line, language, deps, store, result, _ts_line_text(lines, line))

    for node in nodes:
        if node.type == "assignment_expression":
            if not is_module_scope(node):
                if bindings:
                    message = f"{path}: function-scoped imported-binding reassignment is not resolved"
                    if message not in result.errors:
                        result.errors.append(message)
                continue
            left = node.child_by_field_name("left")
            root_alias = _ts_root_identifier(left, source)
            if root_alias in bindings:
                ambiguous_bindings.add(root_alias)
                result.errors.append(f"{path}:{node.start_point.row + 1}: reassigned dependency binding is not resolved")
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name_node = node.child_by_field_name("name")
            root_alias = _ts_root_identifier(value, source)
            if (
                root_alias in bindings
                and value is not None
                and value.type not in {"call_expression", "new_expression"}
                and _ts_identifier(name_node, source)
            ):
                result.errors.append(f"{path}:{node.start_point.row + 1}: dependency function aliases are not resolved")

    named_nodes: list[tuple[str, Node]] = []
    for node in nodes:
        if node.type not in function_kinds:
            continue
        name = _ts_identifier(node.child_by_field_name("name"), source)
        parent = parents.get(node.id)
        if not name and parent and parent.type == "variable_declarator":
            name = _ts_identifier(parent.child_by_field_name("name"), source)
        if not name and parent and parent.type == "assignment_expression":
            name = _ts_identifier(parent.child_by_field_name("left"), source)
        if name:
            named_nodes.append((name, node))

    occurrences: dict[str, int] = {}
    for name, _ in named_nodes:
        occurrences[name] = occurrences.get(name, 0) + 1
    function_ids: dict[int, str] = {}
    names_to_ids: dict[str, list[str]] = {}

    def function_scope(function_node: Node) -> tuple[str, ...]:
        scope: list[str] = []
        ancestor = parents.get(function_node.id)
        while ancestor is not None and ancestor.id != root.id:
            if ancestor.type in {"class_declaration", "class"}:
                class_name = _ts_identifier(ancestor.child_by_field_name("name"), source)
                scope.append(class_name or f"class@{ancestor.start_point.row + 1}")
            elif ancestor.type in function_kinds:
                nested_name = _ts_identifier(ancestor.child_by_field_name("name"), source)
                ancestor_parent = parents.get(ancestor.id)
                if not nested_name and ancestor_parent and ancestor_parent.type == "variable_declarator":
                    nested_name = _ts_identifier(ancestor_parent.child_by_field_name("name"), source)
                if nested_name:
                    scope.append(nested_name)
            ancestor = parents.get(ancestor.id)
        return tuple(reversed(scope))

    def add_export(exported_name: str, function_id: str, line: int) -> None:
        entries = result.exports.setdefault(path, {}).setdefault(exported_name, [])
        if function_id not in entries:
            entries.append(function_id)

    for name, node in named_nodes:
        line = node.start_point.row + 1
        suffix = f"@{line}" if occurrences[name] > 1 else ""
        function_id = f"{path}::{name}{suffix}"
        function_ids[node.id] = function_id
        names_to_ids.setdefault(name, []).append(function_id)
        line_text = _ts_line_text(lines, line)
        evidence_id = _record_line(store, EvidenceType.FUNCTION, path, line, line_text, 0.9, function=name)
        result.function_evidence[function_id] = evidence_id
        result.call_graph.setdefault(function_id, [])
        result.functions[function_id] = FunctionRecord(
            function_id, path, name, line, language, evidence_id, function_scope(node)
        )

        ancestor = parents.get(node.id)
        while ancestor is not None and ancestor.id != root.id:
            if ancestor.type == "export_statement":
                export_text = _ts_text(ancestor, source).lstrip()
                if not _ts_static_string(ancestor.child_by_field_name("source"), source):
                    add_export("default" if export_text.startswith("export default") else name, function_id, line)
                break
            ancestor = parents.get(ancestor.id)

    # Explicit ES exports (`export { local as publicName }`) are resolved only
    # when the source binding uniquely identifies a function in this module.
    for node in nodes:
        if node.type != "export_statement" or _ts_static_string(node.child_by_field_name("source"), source):
            continue
        line = node.start_point.row + 1
        export_clause = next((child for child in node.named_children if child.type == "export_clause"), None)
        if export_clause:
            for specifier in export_clause.named_children:
                if specifier.type != "export_specifier":
                    continue
                local_node = specifier.child_by_field_name("name") or (specifier.named_children[0] if specifier.named_children else None)
                exported_node = specifier.child_by_field_name("alias")
                local_name = _ts_identifier(local_node, source)
                exported_name = _ts_identifier(exported_node, source) or local_name
                candidates = names_to_ids.get(local_name, [])
                if len(candidates) == 1:
                    add_export(exported_name, candidates[0], line)
                elif candidates:
                    result.errors.append(f"{path}:{line}: exported function {local_name!r} is ambiguous")
        elif _ts_text(node, source).lstrip().startswith("export default"):
            match = re.match(r"export\s+default\s+([A-Za-z_$][\w$]*)", _ts_text(node, source).lstrip())
            if match:
                candidates = names_to_ids.get(match.group(1), [])
                if len(candidates) == 1:
                    add_export("default", candidates[0], line)

    # Support static CommonJS export shapes without inferring exports from names.
    for node in nodes:
        if node.type != "assignment_expression":
            continue
        if not is_module_scope(node):
            continue
        left = _ts_member_chain(node.child_by_field_name("left"), source)
        right = node.child_by_field_name("right")
        line = node.start_point.row + 1
        if left in {"exports", "module.exports"} and right and right.type == "object":
            for prop in right.named_children:
                if prop.type == "shorthand_property_identifier":
                    local_name = _ts_text(prop, source)
                    candidates = names_to_ids.get(local_name, [])
                    if len(candidates) == 1:
                        add_export(local_name, candidates[0], line)
                    elif candidates:
                        result.errors.append(f"{path}:{line}: CommonJS export {local_name!r} is ambiguous")
                elif prop.type == "pair":
                    key = prop.child_by_field_name("key")
                    value = prop.child_by_field_name("value")
                    exported_name = _ts_identifier(key, source) or (_ts_static_string(key, source) or "")
                    local_name = _ts_identifier(value, source)
                    candidates = names_to_ids.get(local_name, [])
                    if exported_name and len(candidates) == 1:
                        add_export(exported_name, candidates[0], line)
                    elif exported_name and candidates:
                        result.errors.append(f"{path}:{line}: CommonJS export {local_name!r} is ambiguous")
        elif left.startswith("module.exports.") or left.startswith("exports."):
            exported_name = left.rsplit(".", 1)[-1]
            local_name = _ts_identifier(right, source)
            candidates = names_to_ids.get(local_name, [])
            if len(candidates) == 1:
                add_export(exported_name, candidates[0], line)
            elif candidates:
                result.errors.append(f"{path}:{line}: CommonJS export {local_name!r} is ambiguous")

    def local_nodes(root_node: Node) -> Iterator[Node]:
        pending = [root_node]
        while pending:
            current = pending.pop()
            yield current
            for child in reversed(current.named_children):
                if child.type in function_kinds and child.id != root_node.id:
                    continue
                pending.append(child)

    def binding_names(node: Node | None) -> set[str]:
        if node is None or node.type in {"type_annotation", "type_arguments", "type_parameters", "accessibility_modifier"}:
            return set()
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            return {_ts_text(node, source)}
        if node.type == "assignment_pattern":
            return binding_names(node.child_by_field_name("left"))
        names: set[str] = set()
        for child in node.named_children:
            names.update(binding_names(child))
        return names

    def shadowed_imports(function_node: Node) -> set[str]:
        shadowed: set[str] = set()
        parameters = function_node.child_by_field_name("parameters") or function_node.child_by_field_name("parameter")
        shadowed.update(binding_names(parameters))
        for child in local_nodes(function_node):
            if child.type == "variable_declarator":
                shadowed.update(binding_names(child.child_by_field_name("name")))
        return shadowed & set(bindings)

    def dependency_symbol_for_call(call: Node, shadowed: set[str] | None = None) -> tuple[str, str] | None:
        shadowed = shadowed or set()
        callee = call.child_by_field_name("function")
        if callee and callee.type in {"subscript_expression", "optional_subscript_expression"}:
            root_alias = _ts_root_identifier(callee, source)
            if root_alias in bindings and root_alias not in shadowed:
                result.errors.append(f"{path}:{call.start_point.row + 1}: computed dependency access is not resolved")
                return None

        if callee and callee.type == "member_expression":
            children = callee.named_children
            object_node = children[0] if children else None
            if object_node and object_node.type == "identifier":
                alias = _ts_identifier(object_node, source)
            elif object_node and object_node.type == "member_expression":
                alias = _ts_root_identifier(object_node, source)
            else:
                alias = ""
            chain = _ts_member_chain(callee, source).split(".") if alias in bindings else []
            if alias in bindings and alias not in ambiguous_bindings and alias not in shadowed:
                if len(chain) < 2 or chain[0] != alias:
                    result.errors.append(f"{path}:{call.start_point.row + 1}: optional or complex dependency member access is not resolved")
                    return None
                pkg, imported = bindings[alias]
                module_prefix = next((_module_subpath(pkg, dep, language) for dep in deps if _package_match(pkg, dep, language)), "")
                symbol = ".".join(part for part in (module_prefix, imported, *chain[1:]) if part)
                return pkg, symbol

        callee_name = _ts_identifier(callee, source)
        if callee_name in bindings and callee_name not in ambiguous_bindings and callee_name not in shadowed:
            pkg, imported = bindings[callee_name]
            if imported:
                module_prefix = next((_module_subpath(pkg, dep, language) for dep in deps if _package_match(pkg, dep, language)), "")
                return pkg, ".".join(part for part in (module_prefix, imported) if part)
            result.errors.append(f"{path}:{call.start_point.row + 1}: direct call through a default or namespace binding is not resolved")
        return None

    def record_js_dependency_call(
        call: Node,
        caller_id: str | None,
        shadowed: set[str] | None = None,
    ) -> None:
        package_symbol = dependency_symbol_for_call(call, shadowed)
        if not package_symbol:
            return
        pkg, symbol = package_symbol
        line = call.start_point.row + 1
        for dep in deps:
            if _package_match(pkg, dep, language):
                evidence_id = _record_line(
                    store, EvidenceType.IMPORT, path, line, _ts_line_text(lines, line), 0.9,
                    package=dep, symbol=symbol, caller=caller_id,
                )
                result.usages.append(DependencyUsage(dep, path, line, symbol, "CALL", 0.9, caller_id, evidence_id))

    def nearest_function(node: Node) -> Node | None:
        ancestor = parents.get(node.id)
        while ancestor is not None and ancestor.id != root.id:
            if ancestor.type in function_kinds:
                return ancestor
            ancestor = parents.get(ancestor.id)
        return None

    # Calls at module initialization time are recorded without a route caller.
    # Calls inside unnamed callbacks are handled as unsupported route/callback
    # flow below; walking their nested expression nodes here can trigger parser
    # recovery edge cases and cannot establish a handler identity.
    for call in nodes:
        if call.type != "call_expression":
            continue
        enclosing_function = nearest_function(call)
        if enclosing_function is None:
            record_js_dependency_call(call, None)

    for name, function_node in named_nodes:
        caller_id = function_ids[function_node.id]
        shadowed = shadowed_imports(function_node)
        local_calls: set[str] = set()
        for call in local_nodes(function_node):
            if call.type != "call_expression":
                continue
            callee = call.child_by_field_name("function")
            callee_name = _ts_identifier(callee, source)
            callee_chain = (
                _ts_member_chain(callee, source)
                if callee and callee.type in {"identifier", "member_expression"}
                else ""
            )
            if callee_chain:
                root_name = callee_chain.split(".", 1)[0]
                result.call_sites.append(CallSite(
                    path, caller_id, callee_chain, call.start_point.row + 1, language,
                    root_name in shadowed or root_name in ambiguous_bindings,
                ))
            package_symbol = dependency_symbol_for_call(call, shadowed)
            target_id: str | None = None
            caller_function = result.functions[caller_id]
            if not package_symbol and callee_name and callee_name not in bindings:
                candidates = names_to_ids.get(callee_name, [])
                same_scope = [
                    candidate for candidate in candidates
                    if result.functions[candidate].scope == caller_function.scope
                ]
                module_scope = [
                    candidate for candidate in candidates
                    if not result.functions[candidate].scope
                ]
                eligible = same_scope or module_scope
                if len(eligible) == 1:
                    target_id = eligible[0]
                elif len(eligible) > 1:
                    result.errors.append(f"{path}:{call.start_point.row + 1}: local call target {callee_name!r} is ambiguous")
            elif not package_symbol and callee_chain.startswith("this."):
                method_name = callee_chain.split(".")[-1]
                candidates = [
                    candidate for candidate in names_to_ids.get(method_name, [])
                    if result.functions[candidate].scope == caller_function.scope
                ]
                if len(candidates) == 1:
                    target_id = candidates[0]
                elif len(candidates) > 1:
                    result.errors.append(f"{path}:{call.start_point.row + 1}: method call target {callee_chain!r} is ambiguous")
            if target_id and target_id != caller_id:
                local_calls.add(target_id)
                target = result.functions[target_id]
                result.call_edges.append(CallEdge(
                    caller_function.file, caller_function.name, target.file, target.name,
                    call.start_point.row + 1, "same-file static call", 0.9, caller_id, target_id,
                ))
            if package_symbol:
                record_js_dependency_call(call, caller_id, shadowed)
        result.call_graph[caller_id] = sorted(local_calls)

    route_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    for node in nodes:
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if not callee or callee.type != "member_expression":
            continue
        callee_children = callee.named_children
        object_node = callee_children[0] if callee_children else None
        object_name = _ts_identifier(object_node, source) if object_node and object_node.type == "identifier" else ""
        if object_name not in {"app", "router", "server", "api"}:
            continue
        property_node = callee_children[-1] if len(callee_children) > 1 else None
        method = _ts_identifier(property_node, source).lower()
        arguments = node.child_by_field_name("arguments")
        args = arguments.named_children if arguments else []
        if method in route_methods and object_name in {"app", "router", "server", "api"} and len(args) >= 2:
            route = _ts_static_string(args[0], source)
            handler = _ts_identifier(args[1], source)
            if route is None:
                result.errors.append(f"{path}:{node.start_point.row + 1}: dynamic route path was not resolved")
                continue
            handler_ids = names_to_ids.get(handler, [])
            line = node.start_point.row + 1
            imported_handler = bool(handler) and any(
                binding.file == path and binding.local_name == handler
                for binding in result.module_imports
            )
            if len(handler_ids) != 1 and not imported_handler:
                result.errors.append(f"{path}:{line}: route handler is inline, ambiguous, or unresolved")
            evidence_id = _record_line(store, EvidenceType.ROUTE, path, line, _ts_line_text(lines, line), 0.88, method=method.upper(), route=route, handler=handler or "inline/unknown")
            result.exposures.append(ExposureObservation("Express/Node static route", method.upper(), route, path, line, 0.88, handler_ids[0] if len(handler_ids) == 1 else None, evidence_id))
            if imported_handler and len(handler_ids) != 1:
                result.route_handler_refs.append(RouteHandlerRef(len(result.exposures) - 1, handler, path, line))
        elif method == "listen" and object_name in {"app", "server"}:
            line = node.start_point.row + 1
            evidence_id = _record_line(store, EvidenceType.ROUTE, path, line, _ts_line_text(lines, line), 0.72, method="LISTEN", route="*")
            result.exposures.append(ExposureObservation("Node HTTP listener", "LISTEN", "*", path, line, 0.72, None, evidence_id))


def _analyze_go(path: str, text: str, deps: list[str], store: EvidenceStore, result: SourceAnalysis) -> None:
    parser = _ts_parser("go")
    if parser is None:
        result.errors.append(f"{path}: Tree-sitter parser dependencies are unavailable")
        return
    source = text.encode("utf-8", "replace")
    tree = parser.parse(source)
    if tree is None:
        result.errors.append(f"{path}: Go parser timed out")
        return
    root = tree.root_node
    if root.has_error:
        result.errors.append(
            f"{path}: Go syntax recovery was required; AST analysis was skipped for stability"
        )
        return
    lines = text.splitlines()
    nodes, _parents, complete = _ts_walk_with_parents(root, max_nodes=MAX_GO_AST_NODES)
    if not complete:
        result.errors.append(
            f"{path}: Go AST exceeded the {MAX_GO_AST_NODES}-node safety limit; analysis was skipped for stability"
        )
        return
    imports: dict[str, str] = {}
    for node in nodes:
        if node.type != "import_spec":
            continue
        import_path = _ts_static_string(node.child_by_field_name("path"), source)
        if not import_path:
            result.errors.append(f"{path}:{node.start_point.row + 1}: non-static Go import path was not resolved")
            continue
        alias = _ts_identifier(node.child_by_field_name("name"), source) or import_path.rsplit("/", 1)[-1]
        imports[alias] = import_path
        line = node.start_point.row + 1
        for dep in deps:
            if _package_match(import_path, dep, "go"):
                evidence_id = _record_line(store, EvidenceType.IMPORT, path, line, _ts_line_text(lines, line), 0.9, package=dep, import_path=import_path)
                result.usages.append(DependencyUsage(dep, path, line, "", "IMPORT", 0.9, evidence_id=evidence_id))

    functions: list[tuple[str, Node]] = []
    for node in nodes:
        if node.type not in {"function_declaration", "method_declaration"}:
            continue
        name = _ts_identifier(node.child_by_field_name("name"), source)
        if name:
            functions.append((name, node))
    names_to_ids: dict[str, list[str]] = {}
    function_ids: dict[int, str] = {}
    for name, node in functions:
        line = node.start_point.row + 1
        function_id = f"{path}::{name}"
        if function_id in result.function_evidence:
            function_id = f"{function_id}@{line}"
        function_ids[node.id] = function_id
        names_to_ids.setdefault(name, []).append(function_id)
        result.function_evidence[function_id] = _record_line(store, EvidenceType.FUNCTION, path, line, _ts_line_text(lines, line), 0.9, function=name)
        result.call_graph.setdefault(function_id, [])

    for name, function_node in functions:
        caller_id = function_ids[function_node.id]
        local_calls: set[str] = set()
        for call in _ts_walk(function_node):
            if call.type != "call_expression":
                continue
            callee = call.child_by_field_name("function")
            if not callee:
                continue
            if callee.type == "selector_expression":
                alias = _ts_identifier(callee.child_by_field_name("operand"), source)
                symbol = _ts_identifier(callee.child_by_field_name("field"), source)
                import_path = imports.get(alias)
                if import_path and symbol:
                    line = call.start_point.row + 1
                    for dep in deps:
                        if _package_match(import_path, dep, "go"):
                            evidence_id = _record_line(store, EvidenceType.IMPORT, path, line, _ts_line_text(lines, line), 0.88, package=dep, symbol=symbol, caller=caller_id)
                            result.usages.append(DependencyUsage(dep, path, line, symbol, "CALL", 0.88, caller_id, evidence_id))
            elif callee.type == "identifier":
                called_name = _ts_text(callee, source)
                ids = names_to_ids.get(called_name, [])
                if len(ids) == 1 and ids[0] != caller_id:
                    local_calls.add(ids[0])
        result.call_graph[caller_id] = sorted(local_calls)

    for call in nodes:
        if call.type != "call_expression":
            continue
        callee = call.child_by_field_name("function")
        if not callee or callee.type != "selector_expression":
            continue
        alias = _ts_identifier(callee.child_by_field_name("operand"), source)
        method = _ts_identifier(callee.child_by_field_name("field"), source)
        import_path = imports.get(alias, "")
        args_node = call.child_by_field_name("arguments")
        args = args_node.named_children if args_node else []
        line = call.start_point.row + 1
        if method == "HandleFunc" and len(args) >= 2:
            route = _ts_static_string(args[0], source)
            handler = _ts_identifier(args[1], source)
            if route is None:
                result.errors.append(f"{path}:{line}: dynamic Go handler path was not resolved")
                continue
            ids = names_to_ids.get(handler, [])
            evidence_id = _record_line(store, EvidenceType.ROUTE, path, line, _ts_line_text(lines, line), 0.85, method="HTTP", route=route, handler=handler or "inline/unknown")
            result.exposures.append(ExposureObservation("Go net/http", "HTTP", route, path, line, 0.85, ids[0] if len(ids) == 1 else None, evidence_id))
        elif method == "ListenAndServe" and import_path == "net/http":
            evidence_id = _record_line(store, EvidenceType.ROUTE, path, line, _ts_line_text(lines, line), 0.75, method="LISTEN", route="*")
            result.exposures.append(ExposureObservation("Go net/http listener", "LISTEN", "*", path, line, 0.75, None, evidence_id))


_JS_SOURCE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_MAX_GRAPH_FUNCTIONS = 50_000
_MAX_GRAPH_EDGES = 100_000


def _resolve_js_module(importer: str, specifier: str, files: dict[str, str]) -> tuple[str | None, str | None]:
    """Resolve a relative JS/TS import only when one supported workspace file matches."""
    if not specifier.startswith("."):
        return None, None
    normalized_specifier = specifier.replace("\\", "/")
    suffix = PurePosixPath(normalized_specifier).suffix.lower()
    if suffix and suffix not in _JS_SOURCE_SUFFIXES:
        return None, None  # Assets and non-source imports are outside this call graph.
    base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), normalized_specifier))
    if base == ".." or base.startswith("../") or base.startswith("/"):
        return None, f"relative module import {specifier!r} escapes the analyzed workspace"
    candidates = [base] if suffix else [f"{base}{ext}" for ext in _JS_SOURCE_SUFFIXES]
    if not suffix:
        candidates.extend(f"{base}/index{ext}" for ext in _JS_SOURCE_SUFFIXES)
    matches = sorted({candidate for candidate in candidates if candidate in files})
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, f"relative module import {specifier!r} is ambiguous: {', '.join(matches)}"
    return None, f"relative module import {specifier!r} could not be resolved"


def _python_module_index(files: dict[str, str]) -> dict[str, list[str]]:
    """Index only Python modules whose workspace path gives a deterministic name."""
    index: dict[str, list[str]] = {}
    for path in sorted(files):
        if PurePosixPath(path).suffix.lower() != ".py":
            continue
        parts = list(PurePosixPath(path).parts)
        module_parts = parts[:-1] if parts[-1] == "__init__.py" else [*parts[:-1], PurePosixPath(path).stem]
        aliases = {".".join(module_parts)} if module_parts else set()

        # A src/ layout establishes the module root below that directory.
        for i, part in enumerate(parts[:-1]):
            if part == "src":
                suffix_parts = parts[i + 1:-1] if parts[-1] == "__init__.py" else [*parts[i + 1:-1], PurePosixPath(path).stem]
                if suffix_parts:
                    aliases.add(".".join(suffix_parts))

        # A package root is established by its __init__.py; prefer the outer
        # package root so nested modules retain their full qualified name.
        for i in range(len(parts) - 1):
            package_init = "/".join((*parts[:i + 1], "__init__.py"))
            if package_init in files:
                suffix_parts = parts[i:-1] if parts[-1] == "__init__.py" else [*parts[i:-1], PurePosixPath(path).stem]
                if suffix_parts:
                    aliases.add(".".join(suffix_parts))
                break

        for alias in aliases:
            if alias:
                index.setdefault(alias, []).append(path)
    return {name: sorted(set(paths)) for name, paths in index.items()}


def _python_path_candidates(base: str, module: str) -> list[str]:
    module_path = "/".join(part for part in (base, module.replace(".", "/")) if part)
    return [f"{module_path}.py", f"{module_path}/__init__.py"]


def _resolve_python_module(
    binding: ModuleImport,
    files: dict[str, str],
    module_index: dict[str, list[str]],
) -> tuple[str | None, str | None]:
    if binding.level:
        current = posixpath.dirname(binding.file)
        package_dirs: list[str] = []
        while current and f"{current}/__init__.py" in files:
            package_dirs.append(current)
            current = posixpath.dirname(current)
        if binding.level > len(package_dirs):
            return None, f"relative Python import at {binding.file}:{binding.line} has no established package base"
        base = package_dirs[binding.level - 1]
        matches = sorted({path for path in _python_path_candidates(base, binding.specifier) if path in files})
    else:
        matches = module_index.get(binding.specifier, [])

    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, f"Python module {binding.specifier!r} is ambiguous: {', '.join(matches)}"
    return None, f"Python module {binding.specifier!r} could not be resolved"


def _link_workspace_modules(
    analysis: SourceAnalysis,
    files: dict[str, str],
    dependencies: list[str],
) -> None:
    """Resolve bounded workspace imports, callsites, and imported route handlers."""
    if len(analysis.module_imports) > _MAX_GRAPH_EDGES:
        analysis.module_imports = analysis.module_imports[:_MAX_GRAPH_EDGES]
        analysis.errors.append("Module binding limit reached; reachability may be incomplete")
    if len(analysis.call_sites) > _MAX_GRAPH_EDGES:
        analysis.call_sites = analysis.call_sites[:_MAX_GRAPH_EDGES]
        analysis.errors.append("Callsite limit reached; reachability may be incomplete")

    module_index = _python_module_index(files)
    resolved: dict[tuple[str, str], list[tuple[ModuleImport, str, str, str]]] = {}
    python_stdlib = getattr(sys, "stdlib_module_names", set())

    for binding in analysis.module_imports:
        if binding.language in {"javascript", "typescript", "tsx"}:
            target_file, error = _resolve_js_module(binding.file, binding.specifier, files)
            if error:
                analysis.errors.append(f"{binding.file}:{binding.line}: {error}")
                continue
            if target_file is None:
                continue
            resolved_mode, symbol = binding.mode, binding.imported_name
        elif binding.language == "python":
            module_root = _package_root(binding.specifier, "python") if binding.specifier else ""
            is_dependency = bool(binding.specifier) and any(
                _package_match(binding.specifier, dep, "python") for dep in dependencies
            )
            is_stdlib = bool(module_root) and module_root in python_stdlib
            if not binding.level and (is_dependency or is_stdlib):
                continue
            target_file, error = _resolve_python_module(binding, files, module_index)
            if error:
                if not binding.level and binding.specifier and not is_dependency and not is_stdlib:
                    analysis.errors.append(f"{binding.file}:{binding.line}: unresolved Python import {binding.specifier!r}")
                elif binding.level:
                    analysis.errors.append(f"{binding.file}:{binding.line}: {error}")
                continue
            if target_file is None:
                continue
            resolved_mode, symbol = binding.mode, binding.imported_name
            if binding.mode == "from" and symbol:
                if symbol not in analysis.exports.get(target_file, {}):
                    submodule = f"{binding.specifier}.{symbol}".strip(".")
                    candidates = module_index.get(submodule, []) if not binding.level else [
                        path for path in _python_path_candidates(posixpath.dirname(target_file), symbol)
                        if path in files
                    ]
                    candidates = sorted(set(candidates))
                    if len(candidates) == 1:
                        target_file, resolved_mode, symbol = candidates[0], "namespace", ""
                    elif len(candidates) > 1:
                        analysis.errors.append(f"{binding.file}:{binding.line}: imported Python submodule {submodule!r} is ambiguous")
                        continue
        else:
            continue

        key = (binding.file, binding.local_name)
        entry = (binding, target_file, resolved_mode, symbol)
        if entry not in resolved.setdefault(key, []):
            resolved[key].append(entry)

    def resolve_export(target_file: str, symbol: str, binding: ModuleImport, line: int) -> str | None:
        candidates = analysis.exports.get(target_file, {}).get(symbol, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            analysis.errors.append(f"{binding.file}:{line}: imported function {symbol!r} is ambiguous in {target_file}")
        else:
            analysis.errors.append(f"{binding.file}:{line}: imported function {symbol!r} was not found in {target_file}")
        return None

    def target_for_chain(
        binding: ModuleImport,
        target_file: str,
        resolved_mode: str,
        imported_symbol: str,
        chain: str,
        line: int,
    ) -> str | None:
        parts = chain.split(".")
        if not parts or parts[0] != binding.local_name:
            return None
        suffix = parts[1:]
        if resolved_mode in {"named", "default", "from"}:
            if suffix:
                analysis.errors.append(f"{binding.file}:{line}: imported callable member access {chain!r} is unsupported")
                return None
            symbol = "default" if resolved_mode == "default" else imported_symbol
        elif resolved_mode == "module_root":
            module_tail = binding.specifier.split(".")[1:]
            if suffix[:len(module_tail)] != module_tail:
                analysis.errors.append(f"{binding.file}:{line}: Python module alias path {chain!r} does not match {binding.specifier!r}")
                return None
            symbol = ".".join(suffix[len(module_tail):])
        elif resolved_mode in {"namespace", "module_alias"}:
            symbol = ".".join(suffix)
        else:
            analysis.errors.append(f"{binding.file}:{line}: imported call binding mode {resolved_mode!r} is unsupported")
            return None
        if not symbol:
            analysis.errors.append(f"{binding.file}:{line}: module binding {binding.local_name!r} was called without a static function member")
            return None
        return resolve_export(target_file, symbol, binding, line)

    for site in analysis.call_sites:
        if site.shadowed:
            continue
        root_name = site.callee.split(".", 1)[0]
        candidates = resolved.get((site.file, root_name), [])
        if not candidates:
            continue
        unique_targets = {(item[1], item[2], item[3]) for item in candidates}
        if len(unique_targets) != 1:
            analysis.errors.append(f"{site.file}:{site.line}: imported binding {root_name!r} is ambiguous")
            continue
        binding, target_file, resolved_mode, imported_symbol = candidates[0]
        target_id = target_for_chain(binding, target_file, resolved_mode, imported_symbol, site.callee, site.line)
        if not target_id:
            continue
        source_function = analysis.functions.get(site.caller_id)
        target_function = analysis.functions.get(target_id)
        if not source_function or not target_function:
            analysis.errors.append(f"{site.file}:{site.line}: call graph function identity was incomplete")
            continue
        if target_id not in analysis.call_graph.setdefault(site.caller_id, []):
            if len(analysis.call_edges) >= _MAX_GRAPH_EDGES:
                analysis.errors.append("Call graph edge limit reached; reachability may be incomplete")
                continue
            analysis.call_graph[site.caller_id].append(target_id)
            analysis.call_edges.append(CallEdge(
                source_function.file, source_function.name, target_function.file, target_function.name,
                site.line, "workspace import resolved", 0.9, site.caller_id, target_id,
            ))

    for ref in analysis.route_handler_refs:
        candidates = resolved.get((ref.file, ref.local_name), [])
        if len(candidates) != 1:
            analysis.errors.append(f"{ref.file}:{ref.line}: Route handler could not be resolved statically.")
            continue
        binding, target_file, resolved_mode, imported_symbol = candidates[0]
        if resolved_mode not in {"named", "default", "from"}:
            analysis.errors.append(f"{ref.file}:{ref.line}: Route handler could not be resolved statically.")
            continue
        symbol = "default" if resolved_mode == "default" else imported_symbol
        target_id = resolve_export(target_file, symbol, binding, ref.line)
        if target_id:
            analysis.exposures[ref.exposure_index] = replace(analysis.exposures[ref.exposure_index], handler=target_id)

    if len(analysis.call_graph) > _MAX_GRAPH_FUNCTIONS:
        keep = set(sorted(analysis.call_graph)[:_MAX_GRAPH_FUNCTIONS])
        analysis.call_graph = {
            caller: [target for target in targets if target in keep]
            for caller, targets in analysis.call_graph.items() if caller in keep
        }
        analysis.functions = {key: value for key, value in analysis.functions.items() if key in keep}
        analysis.function_evidence = {key: value for key, value in analysis.function_evidence.items() if key in keep}
        analysis.call_edges = [edge for edge in analysis.call_edges if edge.source_id in keep and edge.target_id in keep]
        analysis.errors.append("Call graph function limit reached; reachability may be incomplete")

    graph_edges = [
        (caller, target)
        for caller in sorted(analysis.call_graph)
        for target in sorted(set(analysis.call_graph[caller]))
    ]
    if len(graph_edges) > _MAX_GRAPH_EDGES:
        retained = set(graph_edges[:_MAX_GRAPH_EDGES])
        analysis.call_graph = {
            caller: [target for target in targets if (caller, target) in retained]
            for caller, targets in analysis.call_graph.items()
        }
        analysis.call_edges = [edge for edge in analysis.call_edges if (edge.source_id, edge.target_id) in retained]
        analysis.errors.append("Call graph edge limit reached; reachability may be incomplete")

    for caller in analysis.call_graph:
        analysis.call_graph[caller] = sorted(set(analysis.call_graph[caller]))

    queue: list[str] = []
    edge_by_pair = {(edge.source_id, edge.target_id): edge for edge in analysis.call_edges}
    for exposure in sorted(analysis.exposures, key=lambda item: (item.file, item.line, item.route)):
        if exposure.handler and exposure.handler in analysis.call_graph and exposure.handler not in analysis.route_parents:
            analysis.route_parents[exposure.handler] = None
            analysis.route_depths[exposure.handler] = 0
            analysis.route_origins[exposure.handler] = f"{exposure.method} {exposure.route} ({exposure.file}:{exposure.line})"
            queue.append(exposure.handler)

    cursor = 0
    while cursor < len(queue):
        current = queue[cursor]
        cursor += 1
        current_depth = analysis.route_depths[current]
        targets = analysis.call_graph.get(current, [])
        if current_depth >= analysis.max_graph_depth:
            if targets:
                analysis.traversal_truncated = True
            continue
        for target in targets:
            if target in analysis.route_parents:
                continue
            analysis.route_parents[target] = current
            analysis.route_depths[target] = current_depth + 1
            analysis.route_origins[target] = analysis.route_origins[current]
            edge = edge_by_pair.get((current, target))
            if edge:
                analysis.route_parent_edges[target] = edge
            queue.append(target)


def analyze_source_files(
    files: dict[str, str],
    dependencies: list[str],
    evidence_store: EvidenceStore | None = None,
    *,
    max_graph_depth: int = 64,
) -> SourceAnalysis:
    """Analyze a bounded mapping of relative source paths to text contents."""
    store = evidence_store or EvidenceStore()
    result = SourceAnalysis()
    if max_graph_depth < 0:
        result.errors.append("Negative call graph depth was clamped to zero")
        max_graph_depth = 0
    if max_graph_depth > 256:
        result.errors.append("Call graph depth exceeded the 256-edge bound and was clamped")
        max_graph_depth = 256
    result.max_graph_depth = max_graph_depth
    dependency_names = sorted(set(dependencies), key=str.lower)
    normalized_files: dict[str, str] = {}
    for raw_path, text in sorted(files.items(), key=lambda item: str(item[0])):
        path = str(PurePosixPath(raw_path.replace("\\", "/")))
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}:
            continue
        if not isinstance(text, str):
            result.errors.append(f"{path}: source content is not text")
            continue
        try:
            source_bytes = text.encode("utf-8", "strict")
        except UnicodeEncodeError:
            result.errors.append(f"{path}: source contains invalid Unicode and was skipped")
            continue
        if len(source_bytes) > 1_000_000:
            result.errors.append(f"{path}: source exceeds 1 MB analyzer limit")
            continue
        if path in normalized_files:
            result.errors.append(f"{path}: duplicate normalized source path is ambiguous")
            continue
        normalized_files[path] = text

    for path, text in normalized_files.items():
        suffix = PurePosixPath(path).suffix.lower()
        result.files_scanned.append(path)
        result.file_evidence[path] = _record_file(path, text, store)
        if suffix == ".py":
            _analyze_python(path, text, dependency_names, store, result)
        elif suffix == ".go":
            _analyze_go(path, text, dependency_names, store, result)
        else:
            language = "tsx" if suffix == ".tsx" else "typescript" if suffix == ".ts" else "javascript"
            _analyze_js(path, text, language, dependency_names, store, result)
    _link_workspace_modules(result, normalized_files, dependency_names)
    return result
