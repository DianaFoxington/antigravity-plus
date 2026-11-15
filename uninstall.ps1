$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>= 18) is required."
    exit 1
}

& node (Join-Path $ScriptDir "cli.js") unpatch @args
