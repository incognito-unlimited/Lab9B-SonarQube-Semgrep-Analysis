# Reproducible Semgrep scan for Lab 9B.
# Run from the repository root after: python -m pip install -r requirements.txt
$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

Write-Host "semgrep $(semgrep --version)"
semgrep scan `
  --config p/python `
  --config config/semgrep/python-security.yml `
  --metrics off `
  --disable-version-check `
  --json `
  --output evidence/semgrep/semgrep.json `
  application/src

semgrep scan `
  --config p/python `
  --config config/semgrep/python-security.yml `
  --metrics off `
  --disable-version-check `
  --output evidence/semgrep/semgrep.txt `
  application/src

Write-Host "JSON: evidence/semgrep/semgrep.json"
Write-Host "TEXT: evidence/semgrep/semgrep.txt"
