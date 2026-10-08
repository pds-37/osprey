from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import analyze_source_files
from osprey.core.models import ReachabilityStatus
from osprey.core.symbols import extract_osv_vulnerable_symbols


def test_osv_symbols_are_scoped_to_matching_package_and_ecosystem():
    advisory = {
        "id": "GHSA-example",
        "database_specific": {"symbols": ["unscoped_root_symbol"]},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "other-package"},
                "ecosystem_specific": {"symbols": ["wrong_package"]},
            },
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ecosystem_specific": {"symbols": ["template"]},
            },
            {
                "package": {"ecosystem": "PyPI", "name": "lodash"},
                "database_specific": {"symbols": ["wrong_ecosystem"]},
            },
        ],
    }
    mappings = extract_osv_vulnerable_symbols(
        advisory, package="lodash", ecosystem="npm"
    )
    assert [mapping.symbol for mapping in mappings] == ["template"]
    assert mappings[0].package == "lodash"
    assert mappings[0].ecosystem == "npm"
    assert mappings[0].vulnerability_id == "GHSA-example"
    assert mappings[0].source == "OSV affected[1].ecosystem_specific.symbols"
    assert mappings[0].confidence > 0
    assert mappings[0].limitations


def test_osv_unscoped_symbols_remain_unknown():
    advisory = {
        "id": "CVE-2026-12345",
        "database_specific": {"symbols": ["template"]},
        "affected": [
            {"ecosystem_specific": {"symbols": ["also_unscoped"]}},
        ],
    }
    mappings = extract_osv_vulnerable_symbols(
        advisory, package="lodash", ecosystem="npm"
    )
    assert mappings == []


def test_pypi_distribution_and_import_name_aliases_are_normalized_for_mapping_scope():
    advisory = {
        "id": "PYSEC-example",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "my_package"},
                "ecosystem_specific": {"symbols": ["unsafe"]},
            }
        ],
    }
    mappings = extract_osv_vulnerable_symbols(
        advisory, package="my-package", ecosystem="pypi"
    )
    assert len(mappings) == 1
    assert mappings[0].symbol == "unsafe"


def test_mismatched_typed_symbol_mapping_returns_unknown():
    analysis = analyze_source_files(
        {
            "app.js": 'import { template } from "lodash";\n'
            'function handler() { return template(input); }\n'
            'app.post("/render", handler);\n'
        },
        ["lodash"],
    )
    result = analyze_reachability(
        analysis,
        package="lodash",
        ecosystem="npm",
        vulnerable_symbols=[
            {
                "ecosystem": "npm",
                "package": "other-package",
                "symbol": "template",
                "source": "OSV affected[0].ecosystem_specific.symbols",
                "confidence": 0.9,
            }
        ],
    )
    assert result.status == ReachabilityStatus.UNKNOWN
    assert "not scoped" in result.explanation


def test_typed_mapping_provenance_and_advisory_evidence_reach_result():
    advisory = {
        "id": "GHSA-template",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ecosystem_specific": {"symbols": ["template"]},
            }
        ],
    }
    mapping = extract_osv_vulnerable_symbols(
        advisory, package="lodash", ecosystem="npm"
    )[0]
    analysis = analyze_source_files(
        {
            "app.js": 'import { template } from "lodash";\n'
            'function handler() { return template(input); }\n'
            'app.post("/render", handler);\n'
        },
        ["lodash"],
    )
    result = analyze_reachability(
        analysis,
        package="lodash",
        ecosystem="npm",
        vulnerable_symbols=[mapping],
        symbol_evidence_ids=["E-OSV-ADVISORY"],
    )
    assert result.status == ReachabilityStatus.REACHABLE
    assert "OSV affected[0].ecosystem_specific.symbols" in result.explanation
    assert result.confidence <= mapping.confidence
    assert "E-OSV-ADVISORY" in result.evidence
    assert any("does not prove runtime" in item for item in result.limitations)


def test_qualified_advisory_symbol_does_not_match_same_named_unrelated_call():
    analysis = analyze_source_files(
        {
            "app.js": 'import * as lodash from "lodash";\n'
            'function handler() { return lodash.safe(input); }\n'
            'app.post("/work", handler);\n'
        },
        ["lodash"],
    )
    result = analyze_reachability(
        analysis,
        package="lodash",
        vulnerable_symbols=["lodash.other_module.safe"],
    )
    assert result.status == ReachabilityStatus.NOT_REACHABLE
    assert result.path == ()
