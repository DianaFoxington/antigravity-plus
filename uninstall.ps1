$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>= 18) is required."
    exit 1
}

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { "" }
$CliPath = if ($ScriptDir -and (Test-Path -LiteralPath $ScriptDir)) { Join-Path $ScriptDir "cli.js" } else { "" }

if (-not $CliPath -or -not (Test-Path -LiteralPath $CliPath)) {
    $Candidates = @(
        (Join-Path $HOME ".gemini\antigravity-plus-src\cli.js"),
        (Join-Path $HOME ".gemini\agy-unlocker\runtime\cli.js")
    )
    $CliPath = $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $CliPath) {
    Write-Error "Could not locate cli.js. Clone the repo or run uninstall.ps1 from the antigravity-plus directory."
    exit 1
}

& node $CliPath unpatch @args
