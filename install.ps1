$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>= 18) is required. Install it from https://nodejs.org/ and re-run."
    exit 1
}

$ScriptDir = if ($MyInvocation.MyCommand.Definition) { Split-Path -Parent $MyInvocation.MyCommand.Definition } else { "" }
$CliPath = if ($ScriptDir) { Join-Path $ScriptDir "cli.js" } else { "" }

if (-not $CliPath -or -not (Test-Path -LiteralPath $CliPath)) {
    $InstallHome = Join-Path $HOME ".gemini\antigravity-plus-src"
    $ZipPath = Join-Path $env:TEMP "antigravity-plus-main.zip"
    Write-Host "Downloading Antigravity Plus from GitHub..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://github.com/DianaFoxington/antigravity-plus/archive/refs/heads/main.zip" -OutFile $ZipPath -UseBasicParsing
    if (Test-Path -LiteralPath $InstallHome) { Remove-Item -LiteralPath $InstallHome -Recurse -Force }
    $ExtractTmp = Join-Path $env:TEMP ("agyp-" + [Guid]::NewGuid().ToString("N"))
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractTmp -Force
    $ExtractedRoot = Get-ChildItem -LiteralPath $ExtractTmp -Directory | Select-Object -First 1
    New-Item -ItemType Directory -Path (Split-Path -Parent $InstallHome) -Force | Out-Null
    Move-Item -LiteralPath $ExtractedRoot.FullName -Destination $InstallHome -Force
    Remove-Item -LiteralPath $ExtractTmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
    $CliPath = Join-Path $InstallHome "cli.js"
}

& node $CliPath patch @args
