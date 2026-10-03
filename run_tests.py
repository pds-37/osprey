"""GuardianOS unified test runner."""

import os
import sys

# Ensure pytest doesn't try to load unneeded DLLs blocked by Windows AppLocker
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

if __name__ == "__main__":
    import pytest
    args = sys.argv[1:] if len(sys.argv) > 1 else ["tests", "-v"]
    exit_code = pytest.main(args)
    sys.exit(exit_code)
