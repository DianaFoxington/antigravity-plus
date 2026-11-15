$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Download-FastFile {
    param([string]$Url, [string]$OutFile, [switch]$ShowBar)
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        $curlArgs = @("-fL", "--retry", "2", "-o", $OutFile, $Url)
        if ($ShowBar) { $curlArgs = @("-#") + $curlArgs } else { $curlArgs = @("-sS") + $curlArgs }
        & curl.exe @curlArgs
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $OutFile)) { return }
    }
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

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

    Write-Host "Node.js not found. Downloading Node.js v22 LTS installer (~25 MB)..." -ForegroundColor Cyan
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
    try {
        $sums = Invoke-RestMethod -Uri "https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt"
        $m = [regex]::Match([string]$sums, "(node-v[\d.]+-$arch\.msi)")
        if (-not $m.Success) { throw "Could not find Node.js $arch MSI." }
        $msiUrl = "https://nodejs.org/dist/latest-v22.x/$($m.Groups[1].Value)"
        $msiPath = Join-Path $env:TEMP $m.Groups[1].Value
        Download-FastFile -Url $msiUrl -OutFile $msiPath -ShowBar
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`"$msiPath`"", "/qn", "/norestart" -Wait
        Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
        Refresh-SessionPath
        if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles "nodejs\node.exe")) {
            $env:Path = "$(Join-Path $env:ProgramFiles 'nodejs');$env:Path"
        }
    } catch {
        Write-Warning "Direct Node.js download failed: $($_.Exception.Message)"
    }

    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Error "Node.js (>= 18) is required. Install it from https://nodejs.org/ and re-run."
        exit 1
    }
}

function Install-AntigravityDesktop {
    Write-Host "Antigravity Desktop not found. Downloading official installer directly (skipping winget bloat)..." -ForegroundColor Cyan
    $archTag = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
    try {
        $vers = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/g/Google/Antigravity" -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $latestDir = ($vers | Where-Object { $_.type -eq "dir" } | Sort-Object { [version]($_.name -replace '[^0-9.]', '') } -Descending | Select-Object -First 1).name
        $files = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/g/Google/Antigravity/$latestDir" -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $instYamlMeta = $files | Where-Object { $_.name -like "*installer*.yaml" } | Select-Object -First 1
        $yamlText = Invoke-RestMethod -Uri $instYamlMeta.download_url -Headers @{ "User-Agent" = "antigravity-plus-installer" }
        $urls = [regex]::Matches([string]$yamlText, "InstallerUrl:\s*(https://\S+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
        $exeUrl = ($urls | Where-Object { $_ -match $archTag } | Select-Object -First 1)
        if (-not $exeUrl) { $exeUrl = $urls | Select-Object -First 1 }
        if (-not $exeUrl) { throw "Could not find installer URL in manifest." }
        $exePath = Join-Path $env:TEMP "Antigravity-Setup.exe"
        Download-FastFile -Url $exeUrl -OutFile $exePath -ShowBar
        Write-Host "Installing Antigravity Desktop silently..." -ForegroundColor Cyan
        Start-Process -FilePath $exePath -ArgumentList "/S" -Wait
        Remove-Item -LiteralPath $exePath -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        return
    } catch {
        Write-Warning "Direct Antigravity fetch failed: $($_.Exception.Message)"
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            & winget install --id Google.Antigravity --exact --silent --accept-package-agreements --accept-source-agreements
            if ($LASTEXITCODE -eq 0) { return }
        }
        Write-Error "Failed to install Antigravity Desktop automatically."
        exit 1
    }
}

Ensure-NodeJs

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { "" }
$CliPath = if ($ScriptDir -and (Test-Path -LiteralPath $ScriptDir)) { Join-Path $ScriptDir "cli.js" } else { "" }

if (-not $CliPath -or -not (Test-Path -LiteralPath $CliPath)) {
    $InstallHome = Join-Path $HOME ".gemini\antigravity-plus-src"
    $ZipPath = Join-Path $env:TEMP "antigravity-plus-main.zip"
    Write-Host "Downloading Antigravity Plus (~380 KB)..." -ForegroundColor Cyan
    Download-FastFile -Url "https://github.com/DianaFoxington/antigravity-plus/archive/refs/heads/main.zip" -OutFile $ZipPath
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
