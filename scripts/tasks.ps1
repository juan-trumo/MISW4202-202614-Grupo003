# Equivalente del Makefile para Windows sin make.
# Uso: powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 <tarea>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("env", "up", "down", "reset", "health", "logs", "lint", "test-unit", "test", "experiment", "report")]
    [string]$Task
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$compose = @("compose", "-f", "docker-compose.yml", "-f", "docker-compose.experiment.yml")

function Invoke-Checked([string]$exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Ensure-Env {
    if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
}

switch ($Task) {
    "env"        { Ensure-Env }
    "up"         { Ensure-Env; Invoke-Checked "docker" ($compose + @("up", "-d", "--build", "--wait")) }
    "down"       { Invoke-Checked "docker" ($compose + @("down")) }
    "reset"      { Invoke-Checked "docker" ($compose + @("down", "-v")) }
    "health"     { Invoke-Checked "python" @("scripts/check_health.py") }
    "logs"       { Invoke-Checked "docker" ($compose + @("logs", "-f", "--tail=100")) }
    "lint"       { Invoke-Checked "python" @("-m", "ruff", "check", ".") }
    "test-unit"  { Invoke-Checked "python" @("-m", "pytest", "common/tests", "services", "-q") }
    "test"       { Invoke-Checked "python" @("-m", "pytest", "-q") }
    "experiment" { Invoke-Checked "python" @("experiment/run.py") }
    "report"     { Invoke-Checked "python" @("experiment/report.py") }
}
