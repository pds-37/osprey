import json
from unittest.mock import MagicMock, patch

from guardianos.intel.osv_client import query_live_osv
from guardianos.inventory.models import Ecosystem


def test_backend_osv_client_preserves_only_package_scoped_symbol_mappings():
    payload = {
        "vulns": [
            {
                "id": "GHSA-symbol-scope",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "other-package"},
                        "ranges": [],
                        "ecosystem_specific": {"symbols": ["wrong_function"]},
                    },
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [],
                        "ecosystem_specific": {"symbols": ["template"]},
                    },
                ],
            }
        ]
    }
    response = MagicMock()
    response.status = 200
    response.read.return_value = json.dumps(payload).encode()
    response.__enter__.return_value = response

    with patch("urllib.request.urlopen", return_value=response):
        records = query_live_osv("lodash", "4.17.20", Ecosystem.NPM)

    assert len(records) == 1
    assert records[0].vulnerable_symbols == ["template"]
    assert len(records[0].vulnerable_symbol_mappings) == 1
    mapping = records[0].vulnerable_symbol_mappings[0]
    assert mapping["package"] == "lodash"
    assert mapping["ecosystem"] == "npm"
    assert mapping["symbol"] == "template"
    assert mapping["source"] == "OSV affected[1].ecosystem_specific.symbols"
