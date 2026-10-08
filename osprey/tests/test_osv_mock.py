import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from osprey.fixes import determine_fix_status
from osprey.intel.cache import IntelCache
from osprey.intel.epss_kev import EpssKevClient
from osprey.intel.osv import OsvClient
from osprey.models import Component


def test_cache_closes_sqlite_handles_after_operations(tmp_path: Path):
    cache = IntelCache(cache_dir=tmp_path, offline=True)
    cache.set("osv", "close-check", [{"id": "DEMO"}])
    assert cache.get("osv", "close-check") == [{"id": "DEMO"}]
    cache.clear()
    moved = tmp_path / "renamed-cache.db"
    os.replace(cache.db_path, moved)
    assert moved.exists()


def test_osv_client_query_batch_mocked(tmp_path: Path):
    cache = IntelCache(cache_dir=tmp_path)
    client = OsvClient(cache=cache)

    comp = Component(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-xxxx-1234",
                        "summary": "Prototype pollution in express",
                        "affected": [
                            {
                                "ranges": [
                                    {"events": [{"introduced": "0"}, {"fixed": "4.17.2"}]}
                                ]
                            }
                        ],
                    }
                ]
            }
        ]
    }

    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        res = client.query_components([comp])
        assert mock_post.called
        assert comp.key in res
        assert len(res[comp.key]) == 1
        assert res[comp.key][0]["id"] == "GHSA-xxxx-1234"

    # Second query should come strictly from cache without calling HTTP post
    with patch("httpx.Client.post") as mock_post_2:
        res2 = client.query_components([comp])
        assert not mock_post_2.called
        assert comp.key in res2
        assert len(res2[comp.key]) == 1


def test_osv_client_offline_mode(tmp_path: Path):
    cache = IntelCache(cache_dir=tmp_path, offline=True)
    client = OsvClient(cache=cache, offline=True)

    comp = Component(
        name="lodash",
        version="4.17.20",
        ecosystem="npm",
        purl="pkg:npm/lodash@4.17.20",
    )

    with patch("httpx.Client.post") as mock_post:
        res = client.query_components([comp])
        assert not mock_post.called
        assert comp.key in res
        assert res[comp.key] == []


def test_epss_and_kev_mocked(tmp_path: Path):
    cache = IntelCache(cache_dir=tmp_path)
    client = EpssKevClient(cache=cache)

    mock_kev_resp = MagicMock()
    mock_kev_resp.status_code = 200
    mock_kev_resp.json.return_value = {
        "vulnerabilities": [{"cveID": "CVE-2023-49463"}]
    }

    mock_epss_resp = MagicMock()
    mock_epss_resp.status_code = 200
    mock_epss_resp.json.return_value = {
        "data": [{"cve": "CVE-2023-49463", "epss": "0.1523"}]
    }

    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = [mock_kev_resp, mock_epss_resp]

        kev_catalog = client.get_cisa_kev_catalog()
        assert "CVE-2023-49463" in kev_catalog

        epss_map = client.get_epss_scores(["CVE-2023-49463"])
        assert epss_map.get("CVE-2023-49463") == 0.1523


def test_determine_fix_status():
    raw_vuln = {
        "id": "GHSA-libheif-test",
        "affected": [
            {
                "package": {"ecosystem": "Debian"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.19.8"}],
                    }
                ]
            }
        ],
    }

    fix = determine_fix_status(installed_version="1.17.0", raw_vuln=raw_vuln, ecosystem="debian")
    assert fix.status == "upstream fix released"
    assert fix.fixed_version == "1.19.8"
    assert fix.minimal_safe_version == ">= 1.19.8"
    assert "upstream fix released (>= 1.19.8)" in fix.stages["stage_1_upstream"]
    assert fix.stages["stage_2_distro"] == "not tracked yet (roadmap)"


def test_offline_ignores_cache_ttl_entries_older_than_24h(tmp_path: Path):
    """Verify that --offline mode ignores the 24h TTL and successfully loads expired cache entries."""
    cache_dir = tmp_path / "cache"
    cache = IntelCache(cache_dir=cache_dir, ttl_seconds=86400.0, offline=False)

    comp = Component(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
    )
    key = comp.key
    cached_vulns = [{"id": "GHSA-old-vuln-1", "summary": "Old test vulnerability"}]
    cache.set("osv", key, cached_vulns)

    # Artificially age the entry to 48 hours ago (> 24h TTL)
    two_days_ago = time.time() - (48 * 3600)
    with sqlite3.connect(cache.db_path) as conn:
        conn.execute(
            "UPDATE intel_cache SET updated_at = ? WHERE namespace = ? AND cache_key = ?",
            (two_days_ago, "osv", key),
        )
        conn.commit()

    # 1. When offline=False (online mode), expired entries must NOT load (return None)
    online_cache = IntelCache(cache_dir=cache_dir, ttl_seconds=86400.0, offline=False)
    assert online_cache.get("osv", key) is None

    # 2. When offline=True (--offline flag), expired entries MUST still load
    offline_cache = IntelCache(cache_dir=cache_dir, ttl_seconds=86400.0, offline=True)
    res = offline_cache.get("osv", key)
    assert res is not None
    assert res == cached_vulns
    assert res[0]["id"] == "GHSA-old-vuln-1"

    # 3. Verify OsvClient in offline mode uses the expired cached entry with no HTTP calls
    client = OsvClient(cache=offline_cache, offline=True)
    with patch("httpx.Client.post") as mock_post:
        findings = client.query_components([comp])
        assert not mock_post.called
        assert comp.key in findings
        assert len(findings[comp.key]) == 1
        assert findings[comp.key][0]["id"] == "GHSA-old-vuln-1"


def test_offline_remediation_coverage_rejects_stale_empty_advisory_cache(tmp_path: Path):
    cache = IntelCache(cache_dir=tmp_path, offline=True)
    component = Component(name="demo", version="1.2.0", ecosystem="npm", purl="pkg:npm/demo@1.2.0")
    cache.set("osv", component.key, [])
    cache.set("osv_coverage", component.key, {
        "status": "COMPLETE",
        "observed_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
    })
    client = OsvClient(cache=cache, offline=True)
    assert client.query_components([component])[component.key] == []
    assert client.coverage_by_component[component.key] == "STALE"
