$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>= 18) is required. Install it from https://nodejs.org/ and re-run."
    exit 1
}

& node (Join-Path $ScriptDir "cli.js") patch @args
