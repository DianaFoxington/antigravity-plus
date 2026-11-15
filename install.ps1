$ErrorActionPreference = "Stop"

function Refresh-SessionPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath"
}

function Ensure-NodeJs {
    if (Get-Command node -ErrorAction SilentlyContinue) { return }
    $known = @(
        (Join-Path $env:ProgramFiles "nodejs\node.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "nodejs\node.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\nodejs\node.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if ($known) {
        $env:Path = "$(Split-Path -Parent $known);$env:Path"
        return
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Node.js not found. Installing Node.js LTS via winget..." -ForegroundColor Cyan
        & winget install --id OpenJS.NodeJS.LTS --exact --silent --accept-package-agreements --accept-source-agreements
        Refresh-SessionPath
        if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles "nodejs\node.exe")) {
            $env:Path = "$(Join-Path $env:ProgramFiles 'nodejs');$env:Path"
        }
    }
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Error "Node.js (>= 18) is required. Install it from https://nodejs.org/ and re-run."
        exit 1
    }
}

function Install-AntigravityDesktop {
    Write-Host "Antigravity Desktop was not found on this machine. Installing automatically..." -ForegroundColor Cyan
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install --id Google.Antigravity --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Start-Sleep -Seconds 2
            return
        }
    }
    try {
        Write-Host "Fetching official Antigravity Desktop installer..." -ForegroundColor Cyan
        $vers = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/g/Google/Antigravity" -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $latestDir = ($vers | Where-Object { $_.type -eq "dir" } | Sort-Object { [version]($_.name -replace '[^0-9.]', '') } -Descending | Select-Object -First 1).name
        $files = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/g/Google/Antigravity/$latestDir" -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $instYamlMeta = $files | Where-Object { $_.name -like "*installer*.yaml" } | Select-Object -First 1
        $yamlText = Invoke-RestMethod -Uri $instYamlMeta.download_url -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $m = [regex]::Match($yamlText, "InstallerUrl:\s*(https://\S+)")
        if (-not $m.Success) { throw "Could not parse official installer URL." }
        $exeUrl = $m.Groups[1].Value.Trim()
        $exePath = Join-Path $env:TEMP "Antigravity-Setup.exe"
        Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing
        Start-Process -FilePath $exePath -ArgumentList "/S" -Wait
        Remove-Item -LiteralPath $exePath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Failed to auto-install Antigravity Desktop: $($_.Exception.Message)"
        exit 1
    }
}

Ensure-NodeJs

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { "" }
$CliPath = if ($ScriptDir -and (Test-Path -LiteralPath $ScriptDir)) { Join-Path $ScriptDir "cli.js" } else { "" }

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

$PathsModule = Join-Path (Split-Path -Parent $CliPath) "src\paths.js"
$HasPathArg = ($args -contains "--path") -or ($args -contains "-p") -or ($args | Where-Object { $_ -like "--path=*" })
if (-not $HasPathArg) {
    $detected = & node -e "try{console.log(require(process.argv[1]).discoverAntigravityResources())}catch{process.exit(1)}" $PathsModule 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $detected) {
        Install-AntigravityDesktop
    }
}

& node $CliPath patch @args
