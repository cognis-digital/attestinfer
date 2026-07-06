# attestinfer installer (Windows PowerShell). Zero required dependencies.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
Write-Host "==> Using $(& $py --version)"
& $py -m pip install --upgrade pip | Out-Null

if ($args -contains "--fast") {
    Write-Host "==> Installing with optional PyNaCl cross-check"
    & $py -m pip install -e ".[fast]"
} else {
    Write-Host "==> Installing (pure-Python, no third-party deps)"
    & $py -m pip install -e .
}

Write-Host "==> Verifying"
& $py -c "import attestinfer; print('attestinfer', attestinfer.__version__, 'installed OK')"
& $py examples/demo.py | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "==> Demo passed" }
Write-Host "Done. Try:  attestinfer --help"
