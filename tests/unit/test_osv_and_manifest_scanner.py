import unittest
import asyncio
from unittest.mock import patch, MagicMock
from guardianos.intel.osv_client import query_live_osv
from guardianos.inventory.models import Ecosystem
from guardianos.api.v1.sboms import scan_local_workspace


class TestOsvAndManifestScanner(unittest.TestCase):
    @patch("guardianos.intel.osv_client.urllib.request.urlopen")
    def test_query_osv_vulnerabilities_mocked(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"vulns": [{"id": "GHSA-1234", "summary": "Sample bug", "database_specific": {"severity": "HIGH"}}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        results = query_live_osv("lodash", "4.17.15", Ecosystem.NPM)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "GHSA-1234")
        self.assertEqual(results[0].summary, "Sample bug")

    def test_scan_local_workspace_manifests(self):
        # Should scan real workspace manifests
        res = asyncio.run(scan_local_workspace())
        self.assertIsNotNone(res.sbom_id)
        self.assertGreater(res.components_count, 0)
        self.assertGreater(res.relationships_count, 0)
        self.assertTrue(len(res.application) > 0)
