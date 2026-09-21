# quality-checker pre-commit hook (Windows / PowerShell).
#
# INSTALLATION:
#   Copy this file to your project's Git hooks directory as pre-commit:
#     Copy-Item vendor/vietvang/quality-checker/resources/stubs/pre-commit.ps1 .git/hooks/pre-commit
#   Then configure Git to use this PowerShell hook:
#     git config core.hooksPath .git/hooks
#   (or place a small pre-commit wrapper that calls this script).
#
# What it does:
#   Runs the quality checker for the phpcs + phpstan checkers only, failing the
#   commit (exit 1) when any error-level issue is found. Writes a machine-
#   readable JSON report to reports/quality-checker/.

$ErrorActionPreference = 'Stop'

$ReportDir = "reports/quality-checker"
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$output = & php artisan quality:check `
    --only=phpcs,phpstan `
    --fail-on=error `
    --format=json `
    --output="$ReportDir" 2>&1
$exitCode = $LASTEXITCODE

$output | Out-File -FilePath "$ReportDir/quality-report.json" -Encoding utf8

if ($exitCode -eq 0) {
    Write-Host "[quality-checker] PASS - no error-level issues." -ForegroundColor Green
    exit 0
}

Write-Host "[quality-checker] FAIL - error-level issues detected; commit aborted." -ForegroundColor Red
Write-Host "See $ReportDir/quality-report.json for details."
exit 1
