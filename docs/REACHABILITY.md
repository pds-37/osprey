# Osprey Static Reachability

**Updated:** 2026-10-08

## Normal scan flow and result

The CLI attempts reachability as part of `osprey scan`. The backend workspace scan also runs the shared source analyzer after advisory matching, attaches results to affected findings, and passes that evidence into the same deterministic risk engine used by the CLI. Findings persist reachability status, confidence, path, explanation, limitations, and evidence IDs.

`POST /api/v1/analysis/reachability` remains available for a finding and a caller-submitted, bounded bundle of relative-path source files. The response has status, confidence, path, evidence IDs, explanation, and explicit limitations.

- **REACHABLE:** Supported syntax linked an observed HTTP handler through local calls and dependency use to a vulnerable symbol supplied by advisory data. The source route does not establish Internet exposure.
- **NOT_REACHABLE:** Within the scanned/submitted files and supported syntax, an imported dependency was observed but the advisory-mapped vulnerable symbol was not reached from an observed handler.
- **UNKNOWN:** Required route, import, symbol, or parse evidence is missing, unsupported, incomplete, or dynamic. No symbol mapping is treated as `UNKNOWN`, not as a negative result.

`NOT_REACHABLE` is deliberately scoped to the scanned or submitted source files. It does not prove a symbol cannot be reached in omitted files or at runtime. The result's limitations are included in API and CLI JSON output and in `osprey explain`.

Reachability evidence records retain normalized status, confidence, path, edge relationships and locations, reason, basis evidence IDs, and limitations. These structured observations are hashed and persisted; they are analyzer output, not separately persisted immutable callsite records. A stored SHA-256 detects covered content changes but does not make SQLite tamper-proof or establish forensic custody.

## Bounded inter-file analysis — PARTIAL

The shared analyzer builds an explainable, workspace-bounded function call graph for JavaScript, TypeScript, TSX, and Python. It reuses the existing route, import, function, symbol, and evidence extraction. Go retains its earlier local import/call extraction; it is not part of the Phase 3 inter-file graph. Osprey never imports or executes scanned application code.

The graph links observed route handlers to supported same-file calls and calls through resolved workspace imports. A dependency call is treated as vulnerable only when its observed symbol matches an advisory-scoped vulnerable-symbol mapping. An imported package by itself is not a vulnerable-symbol call.

### JavaScript, TypeScript, and TSX modules

Supported workspace imports include ES named/default/namespace imports and static CommonJS `require()` bindings, including destructuring. Named aliases are retained. Relative module resolution checks the exact path and supported `.js`, `.jsx`, `.ts`, `.tsx`, and `index` candidates. It does not emulate bundlers, package exports, path aliases, or arbitrary resolver configuration. Ambiguous or unresolved local imports are not guessed and add a limitation.

Cross-file calls require a static imported binding and a uniquely resolved exported function. The supported examples include:

```ts
import { processData as process } from "./services/data";
process(input);

const service = require("./services/data");
service.processData(input);
```

Only module-scope static `require()` bindings and supported export forms are linked. Dynamic `import()` is not resolved. Function-scoped `require()`, reassigned imported bindings, computed access, unresolved aliases, and unsupported dispatch remain incomplete and produce `UNKNOWN` when they could affect a conclusion.

### Python modules

Supported imports include `from services.parser import parse_document`, `import services.parser` followed by a static member call, and explicit relative imports such as `from .parser import parse_document`. Local modules resolve only when the workspace path or package structure can be established; relative package resolution requires package markers. Ambiguous or unresolved modules are not guessed. Dynamic imports, wildcard imports, runtime import hooks, and other Python import-system behavior remain unsupported.

### Routes, paths, and bounds

The existing route detectors provide the entrypoint observations. An imported route handler is linked only when its module and exported function resolve uniquely. If the handler cannot be resolved, Osprey records `Route handler could not be resolved statically.` and does not claim a route-to-symbol path.

Traversal is cycle-safe: each function is visited once per route closure. The default maximum path depth is 64 edges; callers may configure up to 256. The graph is capped at 50,000 functions and 100,000 edges; module bindings and callsites are each capped at 100,000. Reaching a depth or graph-size limit is an explicit analysis limitation and cannot produce `NOT_REACHABLE`. JavaScript/TypeScript/TSX AST traversal is capped at 4,096 syntax nodes per file. A file over that bound is skipped for stability and contributes an explicit limitation. Workspace file discovery is also bounded by depth, file size, file count, and aggregate source bytes.

`REACHABLE` exposes the route, function sequence, and vulnerable symbol with source locations where available. Same-file and imported call edges remain syntax-derived; they do not have separate callsite evidence records. Evidence IDs continue to identify source-file, function, route, import/call, and advisory records where those records exist.

## Vulnerability-to-symbol mapping — PARTIAL

The internal `VulnerableSymbol` mapping retains ecosystem, affected package, symbol, vulnerability ID, source field, mapping confidence, and limitations. For OSV, Osprey accepts string entries under `symbols` or `vulnerable_symbols` inside an `affected[]` record only when that record explicitly identifies the same package and ecosystem being scanned. Root-level and unscoped symbols, other packages in a multi-package advisory, and non-string values are ignored. Osprey does not infer symbols from package names, advisory prose, or source code.

Mapping confidence describes the advisory-to-package association. It is not exploit probability. Sparse or absent symbol metadata remains `UNKNOWN` / limited symbol coverage. Older explicitly supplied symbol strings remain supported for compatibility but do not carry the structured OSV mapping provenance.

## UNKNOWN conditions and limitations

The analyzer is not a complete call graph or taint engine. It returns `UNKNOWN` when relevant dynamic or ambiguous behavior prevents a supported conclusion, including dynamic `import()` or `require()`, computed dependency property access, reflective access (`getattr` / `getattr`-style calls), unresolved function-value aliases, reassigned bindings, parser recovery, a file exceeding the 4,096-node AST safety bound, unresolved imports, unresolved or ambiguous route handlers, graph truncation, or a vulnerable-symbol call with no supported path from an observed route. Recovered JavaScript/TypeScript/TSX/Go syntax trees are not traversed; Osprey records the skipped file as incomplete. An unresolved route handler is recorded as an explicit limitation; it is not evidence that a vulnerable symbol cannot be reached.

Known gaps include:

- JavaScript/TypeScript/TSX: dynamic `require()`, function-scoped loading, computed property access, reflection, monkey patching, generated code, scope-sensitive shadowing, path aliases, bundler-specific resolution, unresolved module resolution, large/recovered AST files, and complex re-export use.
- Python: dynamic imports, `getattr()` and other reflection, monkey patching, generated code, unresolved imports, wildcard imports, decorators/metaprogramming, runtime dispatch, and unsupported package layouts.
- Both: native extensions, runtime-loaded behavior, framework magic, complex data flow, and calls whose identity depends on runtime state.

Internal call edges are inferred from syntax and do not have separate callsite evidence records. Import/call observations and function/route evidence remain traceable to their source locations; Osprey does not claim a separate evidence record for every local edge. `NOT_REACHABLE` is limited to the supplied files and supported syntax. It does not prove a symbol cannot be reached in omitted files or at runtime, nor does it establish Internet ingress, authentication bypass, exploitability, or production runtime. Confidence describes supported static evidence and mapping quality, not exploit probability.

Use the result as triage evidence and review the cited files and symbols. Missing or ambiguous evidence must remain `UNKNOWN`.

## Static and runtime evidence

Runtime observations are a separate evidence layer and never replace static reachability. `REACHABLE` remains a static route/call/symbol conclusion even when runtime evidence is absent. A current `LOADED` or `EXERCISED` record can strengthen context for the observed environment; stale or absent runtime evidence remains `UNKNOWN`, not a negative result. See [RUNTIME_REALITY.md](RUNTIME_REALITY.md) for what the opt-in Python instrumentation proves and its limits.
