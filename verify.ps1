$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    throw 'Create and configure .venv first; see README.md.'
}

Push-Location $repoRoot
try {
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Backend/API tests failed with exit code $LASTEXITCODE" }

    Push-Location (Join-Path $repoRoot 'osprey')
    try {
        & $python -m pytest -q
        if ($LASTEXITCODE -ne 0) { throw "Osprey shared scanner/CLI tests failed with exit code $LASTEXITCODE" }
    }
    finally { Pop-Location }

    & $python -m pip check
    if ($LASTEXITCODE -ne 0) { throw "pip check failed with exit code $LASTEXITCODE" }

    Push-Location (Join-Path $repoRoot 'frontend')
    try {
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "Frontend build failed with exit code $LASTEXITCODE" }
    }
    finally { Pop-Location }
}
finally { Pop-Location }

Write-Output 'Osprey verification completed successfully.'
