#requires -Version 5.1
<#
.SYNOPSIS
Installs DONZO local dependencies and recon tools.

.DESCRIPTION
This script is intentionally installer-only. It installs Python project
dependencies, bootstraps Go/pipx when needed, installs profile-specific DONZO
tools, and then runs DONZO's local tool preflight. It does not run recon.

Examples:
  powershell -ExecutionPolicy Bypass -File .\scripts\install-donzo-tools.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\install-donzo-tools.ps1 -Profile fast
  powershell -ExecutionPolicy Bypass -File .\scripts\install-donzo-tools.ps1 -Profile deep -RequiredOnly
  powershell -ExecutionPolicy Bypass -File .\scripts\install-donzo-tools.ps1 -Profile all -DryRun
#>

[CmdletBinding()]
param(
    [ValidateSet("fast", "normal", "deep", "all")]
    [string]$Profile = "deep",

    [switch]$RequiredOnly,
    [switch]$SkipPythonDeps,
    [switch]$SkipPrerequisites,
    [switch]$ForceWindowsBbot,
    [switch]$NoPathPersist,
    [switch]$DryRun,

    [int]$CommandTimeoutSeconds = 1800,
    [int]$ToolCheckTimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$IsWindowsHost = ($env:OS -eq "Windows_NT")
if (-not $IsWindowsHost) {
    throw "This installer is written for Windows PowerShell. Use DONZO's tool matrix to adapt it for WSL/Linux."
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ToolsRoot = Join-Path $env:USERPROFILE ".donzo\tools"
$ToolsBin = Join-Path $ToolsRoot "bin"
$GoBin = Join-Path $env:USERPROFILE "go\bin"
$PipxBin = Join-Path $env:USERPROFILE ".local\bin"
$PythonUserScripts = Join-Path $env:APPDATA "Python\Python311\Scripts"
try {
    $PythonUserScriptsOutput = & python -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))" 2>$null
    $ResolvedPythonUserScripts = $PythonUserScriptsOutput | Select-Object -First 1
    if ($ResolvedPythonUserScripts) {
        $PythonUserScripts = ([string]$ResolvedPythonUserScripts).Trim()
    }
}
catch {
    $PythonUserScripts = Join-Path $env:APPDATA "Python\Python311\Scripts"
}

$RequiredByProfile = @{
    fast = @("subfinder", "dnsx", "httpx", "katana")
    normal = @("subfinder", "dnsx", "httpx", "katana", "gau", "waybackurls")
    deep = @("subfinder", "dnsx", "httpx", "katana", "gau", "waybackurls")
}

$OptionalByProfile = @{
    fast = @("nuclei")
    normal = @("naabu", "nuclei")
    deep = @(
        "amass",
        "bbot",
        "uncover",
        "alterx",
        "tlsx",
        "waymore",
        "paramspider",
        "kiterunner",
        "gitleaks",
        "trufflehog",
        "arjun",
        "gf",
        "qsreplace",
        "kxss",
        "naabu",
        "nuclei"
    )
}

$BinaryByTool = @{
    kiterunner = "kr"
}

$VersionArgsByTool = @{
    subfinder = @("-version")
    dnsx = @("-version")
    httpx = @("-version")
    katana = @("-version")
    gau = @("-h")
    waybackurls = @("-h")
    naabu = @("-version")
    nuclei = @("-version")
    amass = @("-version")
    bbot = @("--version")
    uncover = @("-version")
    alterx = @("-version")
    tlsx = @("-version")
    waymore = @("--version")
    paramspider = @("-h")
    kiterunner = @("-h")
    gitleaks = @("version")
    trufflehog = @("--version")
    arjun = @("-h")
    gf = @("-h")
    qsreplace = @("-h")
    kxss = @("-h")
}

$GoPackages = @{
    subfinder = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    dnsx = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    httpx = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    katana = "github.com/projectdiscovery/katana/cmd/katana@latest"
    gau = "github.com/lc/gau/v2/cmd/gau@latest"
    waybackurls = "github.com/tomnomnom/waybackurls@latest"
    naabu = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    nuclei = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    uncover = "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    alterx = "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    tlsx = "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    gf = "github.com/tomnomnom/gf@latest"
    qsreplace = "github.com/tomnomnom/qsreplace@latest"
    kxss = "github.com/Emoe/kxss@latest"
}

$GoFallbackPackages = @{
    gitleaks = "github.com/gitleaks/gitleaks/v8@latest"
    trufflehog = "github.com/trufflesecurity/trufflehog/v3@latest"
}

$PipxPackages = @{
    bbot = "bbot"
    waymore = "waymore"
    paramspider = "git+https://github.com/devanshbatham/ParamSpider.git"
    arjun = "arjun"
}

$ReleaseTools = @{
    amass = @{
        Repo = "owasp-amass/amass"
        Binary = "amass"
        Patterns = @("windows.*amd64.*\.(zip|tar\.gz)$", "windows.*x86_64.*\.(zip|tar\.gz)$")
    }
    kiterunner = @{
        Repo = "assetnote/kiterunner"
        Binary = "kr"
        Patterns = @("windows.*amd64.*\.zip$", "windows.*x86_64.*\.zip$")
    }
    gitleaks = @{
        Repo = "gitleaks/gitleaks"
        Binary = "gitleaks"
        Patterns = @("windows.*x64.*\.(zip|tar\.gz)$", "windows.*amd64.*\.(zip|tar\.gz)$", "windows.*x86_64.*\.(zip|tar\.gz)$")
    }
    trufflehog = @{
        Repo = "trufflesecurity/trufflehog"
        Binary = "trufflehog"
        Patterns = @("windows.*amd64.*\.(zip|tar\.gz)$", "windows.*x86_64.*\.(zip|tar\.gz)$")
    }
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text"
}

function Write-Ok {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Warning $Text
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($DryRun) {
            Write-Info "Would create directory: $Path"
            return
        }
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Add-PathEntry {
    param([string]$Path)
    if (-not $Path) {
        return
    }
    New-Directory -Path $Path
    $sessionParts = @($env:Path -split ";" | Where-Object { $_ })
    if (-not ($sessionParts | Where-Object { $_.Equals($Path, [StringComparison]::OrdinalIgnoreCase) })) {
        $env:Path = "$Path;$env:Path"
        Write-Info "Added to current PATH: $Path"
    }
    if ($NoPathPersist) {
        return
    }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $userParts = @($userPath -split ";" | Where-Object { $_ })
    if (-not ($userParts | Where-Object { $_.Equals($Path, [StringComparison]::OrdinalIgnoreCase) })) {
        $newUserPath = if ($userPath) { "$Path;$userPath" } else { $Path }
        if ($DryRun) {
            Write-Info "Would persist user PATH entry: $Path"
            return
        }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-Info "Persisted user PATH entry: $Path"
    }
}

function Invoke-External {
    param(
        [string]$File,
        [string[]]$Arguments,
        [switch]$Required,
        [int]$TimeoutSeconds = $CommandTimeoutSeconds
    )
    $display = "$File $($Arguments -join ' ')"
    if ($DryRun) {
        Write-Info "Would run: $display"
        return $true
    }
    Write-Info "Running: $display"
    $result = Invoke-NativeCommand -File $File -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
    foreach ($line in $result.Output) {
        if ($line -ne $null -and [string]$line -ne "") {
            Write-Host $line
        }
    }
    if ($result.TimedOut) {
        $message = "Command timed out after ${TimeoutSeconds}s: $display"
        if ($Required) {
            throw $message
        }
        Write-Warn $message
        return $false
    }
    $code = [int]$result.ExitCode
    if ($code -ne 0) {
        if ($Required) {
            throw "Command failed with exit code ${code}: $display"
        }
        Write-Warn "Command failed with exit code ${code}: $display"
        return $false
    }
    return $true
}

function Invoke-NativeCommand {
    param(
        [string]$File,
        [string[]]$Arguments,
        [int]$TimeoutSeconds
    )
    $marker = "__DONZO_EXIT_CODE__="
    $job = Start-Job -ScriptBlock {
        param([string]$InnerFile, [string[]]$InnerArguments, [string]$InnerMarker)
        & $InnerFile @InnerArguments 2>&1 | ForEach-Object { $_ }
        $code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
        Write-Output "$InnerMarker$code"
    } -ArgumentList $File, $Arguments, $marker
    try {
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            return @{
                TimedOut = $true
                ExitCode = 124
                Output = @()
            }
        }
        $received = @(Receive-Job -Job $job)
        $output = New-Object System.Collections.Generic.List[string]
        $exitCode = 0
        foreach ($item in $received) {
            $line = [string]$item
            if ($line.StartsWith($marker, [StringComparison]::Ordinal)) {
                $parsed = 0
                if ([int]::TryParse($line.Substring($marker.Length), [ref]$parsed)) {
                    $exitCode = $parsed
                }
                continue
            }
            $output.Add($line)
        }
        return @{
            TimedOut = $false
            ExitCode = $exitCode
            Output = @($output)
        }
    }
    finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

function Get-ToolBinaryName {
    param([string]$Tool)
    if ($BinaryByTool.ContainsKey($Tool)) {
        return [string]$BinaryByTool[$Tool]
    }
    return $Tool
}

function Get-WindowsExeName {
    param([string]$Name)
    if ($Name.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) {
        return $Name
    }
    return "$Name.exe"
}

function Find-ToolPath {
    param([string]$Tool)
    $binary = Get-ToolBinaryName -Tool $Tool
    $exe = Get-WindowsExeName -Name $binary
    foreach ($dir in @($GoBin, $ToolsBin, $PipxBin, $PythonUserScripts)) {
        $candidate = Join-Path $dir $exe
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
        $candidateNoExe = Join-Path $dir $binary
        if (Test-Path -LiteralPath $candidateNoExe) {
            return $candidateNoExe
        }
    }
    $command = Get-Command $binary -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

function Test-DonzoTool {
    param([string]$Tool)
    $path = Find-ToolPath -Tool $Tool
    if (-not $path) {
        return @{
            Available = $false
            Path = $null
            Error = "not_found"
        }
    }
    $args = if ($VersionArgsByTool.ContainsKey($Tool)) { [string[]]$VersionArgsByTool[$Tool] } else { @("-version") }
    try {
        $result = Invoke-NativeCommand -File $path -Arguments $args -TimeoutSeconds $ToolCheckTimeoutSeconds
        if ($result.TimedOut) {
            return @{
                Available = $true
                Path = $path
                Version = "version_check_timeout"
            }
        }
        $code = [int]$result.ExitCode
        $output = ($result.Output | Where-Object { $_ } | Select-Object -First 1)
        if ($code -eq 0) {
            return @{
                Available = $true
                Path = $path
                Version = [string]$output
            }
        }
        return @{
            Available = $false
            Path = $path
            Error = "version_returned_$code"
        }
    }
    catch {
        return @{
            Available = $false
            Path = $path
            Error = $_.Exception.Message
        }
    }
}

function Install-SystemPackage {
    param(
        [string]$Name,
        [string]$WingetId,
        [string]$ChocoName,
        [string]$ScoopName
    )
    if ($WingetId -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        $ok = Invoke-External -File "winget" -Arguments @(
            "install",
            "--id",
            $WingetId,
            "-e",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements"
        )
        if ($ok) {
            return
        }
    }
    if ($ChocoName -and (Get-Command choco -ErrorAction SilentlyContinue)) {
        $ok = Invoke-External -File "choco" -Arguments @("install", $ChocoName, "-y")
        if ($ok) {
            return
        }
    }
    if ($ScoopName -and (Get-Command scoop -ErrorAction SilentlyContinue)) {
        $ok = Invoke-External -File "scoop" -Arguments @("install", $ScoopName)
        if ($ok) {
            return
        }
    }
    throw "Could not install $Name. Install winget, Chocolatey, or Scoop, or install $Name manually."
}

function Ensure-Python {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Write-Ok "python is available"
        return
    }
    Write-Section "Installing Python"
    Install-SystemPackage -Name "Python" -WingetId "Python.Python.3.11" -ChocoName "python" -ScoopName "python"
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "python is still unavailable after installation."
    }
}

function Ensure-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Ok "git is available"
        return
    }
    Write-Section "Installing Git"
    Install-SystemPackage -Name "Git" -WingetId "Git.Git" -ChocoName "git" -ScoopName "git"
}

function Install-PortableGo {
    Write-Section "Installing portable Go"
    $versionText = Invoke-RestMethod -Uri "https://go.dev/VERSION?m=text" -Headers @{ "User-Agent" = "donzo-tool-installer" }
    $version = (($versionText -split "`n") | Select-Object -First 1).Trim()
    if (-not $version.StartsWith("go")) {
        throw "Could not resolve latest Go version from go.dev."
    }
    $zipUrl = "https://go.dev/dl/$version.windows-amd64.zip"
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) "$version.windows-amd64.zip"
    $extractRoot = Join-Path $ToolsRoot "go-$version"
    $portableGoBin = Join-Path $extractRoot "go\bin"

    if (-not (Test-Path -LiteralPath (Join-Path $portableGoBin "go.exe"))) {
        if ($DryRun) {
            Write-Info "Would download $zipUrl to $zipPath"
            Write-Info "Would extract Go to $extractRoot"
        }
        else {
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -Headers @{ "User-Agent" = "donzo-tool-installer" }
            New-Directory -Path $extractRoot
            Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force
        }
    }
    Add-PathEntry -Path $portableGoBin
}

function Ensure-Go {
    Add-PathEntry -Path $GoBin
    $standardGoBin = "C:\Program Files\Go\bin"
    if (Test-Path -LiteralPath $standardGoBin) {
        Add-PathEntry -Path $standardGoBin
    }
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Ok "go is available"
        return
    }
    Write-Section "Installing Go"
    try {
        Install-SystemPackage -Name "Go" -WingetId "GoLang.Go" -ChocoName "golang" -ScoopName "go"
    }
    catch {
        Write-Warn $_.Exception.Message
        Install-PortableGo
    }
    if (Test-Path -LiteralPath $standardGoBin) {
        Add-PathEntry -Path $standardGoBin
    }
    if (-not (Get-Command go -ErrorAction SilentlyContinue) -and -not $DryRun) {
        throw "go is still unavailable after installation."
    }
}

function Ensure-Pipx {
    Add-PathEntry -Path $PipxBin
    Add-PathEntry -Path $PythonUserScripts
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        Write-Ok "pipx is available"
        return
    }
    Ensure-Python
    Write-Section "Installing pipx"
    [void](Invoke-External -File "python" -Arguments @("-m", "pip", "install", "--user", "--upgrade", "pipx") -Required)
    [void](Invoke-External -File "python" -Arguments @("-m", "pipx", "ensurepath"))
}

function Install-PythonProjectDeps {
    if ($SkipPythonDeps) {
        Write-Info "Skipping Python project dependency install"
        return
    }
    Write-Section "Installing DONZO Python dependencies"
    Push-Location $RepoRoot
    try {
        [void](Invoke-External -File "python" -Arguments @("-m", "pip", "install", "-e", ".[dev]") -Required)
    }
    finally {
        Pop-Location
    }
}

function Install-GoTool {
    param(
        [string]$Tool,
        [string]$Package
    )
    Ensure-Go
    Add-PathEntry -Path $GoBin
    New-Directory -Path $GoBin
    $env:GOBIN = $GoBin
    [void](Invoke-External -File "go" -Arguments @("install", $Package) -Required)
}

function Install-PipxTool {
    param(
        [string]$Tool,
        [string]$Package
    )
    Ensure-Pipx
    [void](Invoke-External -File "python" -Arguments @("-m", "pipx", "install", "--force", $Package) -Required)
}

function Install-GitHubReleaseTool {
    param(
        [string]$Tool,
        [string]$Repo,
        [string]$Binary,
        [string[]]$Patterns
    )
    Add-PathEntry -Path $ToolsBin
    New-Directory -Path $ToolsBin
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    if ($DryRun) {
        Write-Info "Would resolve latest release from $api"
        Write-Info "Would install $Binary into $ToolsBin"
        return
    }
    Write-Info "Resolving latest release for $Repo"
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "donzo-tool-installer" }
    $asset = $null
    foreach ($pattern in $Patterns) {
        $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($asset) {
            break
        }
    }
    if (-not $asset) {
        throw "No Windows amd64 release asset matched for $Repo."
    }

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) "donzo-tool-$Tool-$([Guid]::NewGuid().ToString('N'))"
    $assetPath = Join-Path $tempRoot $asset.name
    $extractRoot = Join-Path $tempRoot "extract"
    try {
        New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $assetPath -Headers @{ "User-Agent" = "donzo-tool-installer" }
        if ($asset.name -match "\.zip$") {
            Expand-Archive -Path $assetPath -DestinationPath $extractRoot -Force
        }
        elseif ($asset.name -match "\.tar\.gz$") {
            tar -xzf $assetPath -C $extractRoot
        }
        else {
            Copy-Item -LiteralPath $assetPath -Destination (Join-Path $extractRoot (Split-Path $assetPath -Leaf)) -Force
        }
        $wanted = @((Get-WindowsExeName -Name $Binary), $Binary)
        $binaryFile = Get-ChildItem -Path $extractRoot -Recurse -File |
            Where-Object { $wanted -contains $_.Name } |
            Select-Object -First 1
        if (-not $binaryFile) {
            throw "Downloaded $($asset.name), but could not find binary $Binary."
        }
        $destination = Join-Path $ToolsBin (Get-WindowsExeName -Name $Binary)
        Copy-Item -LiteralPath $binaryFile.FullName -Destination $destination -Force
        Write-Ok "Installed $Tool to $destination"
    }
    finally {
        $tempBase = [IO.Path]::GetTempPath()
        if ((Test-Path -LiteralPath $tempRoot) -and $tempRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-Tool {
    param(
        [string]$Tool,
        [bool]$RequiredForSelectedProfile
    )
    $status = Test-DonzoTool -Tool $Tool
    if ($status.Available) {
        Write-Ok "$Tool already available at $($status.Path)"
        return $true
    }
    if ($Tool -eq "bbot" -and -not $ForceWindowsBbot) {
        Write-Warn "Skipping bbot on Windows. DONZO skips it by default unless DONZO_FORCE_BBOT is set; rerun with -ForceWindowsBbot to install anyway."
        return $false
    }

    Write-Section "Installing $Tool"
    try {
        if ($GoPackages.ContainsKey($Tool)) {
            Install-GoTool -Tool $Tool -Package ([string]$GoPackages[$Tool])
        }
        elseif ($PipxPackages.ContainsKey($Tool)) {
            Install-PipxTool -Tool $Tool -Package ([string]$PipxPackages[$Tool])
        }
        elseif ($ReleaseTools.ContainsKey($Tool)) {
            $spec = $ReleaseTools[$Tool]
            try {
                Install-GitHubReleaseTool -Tool $Tool -Repo ([string]$spec.Repo) -Binary ([string]$spec.Binary) -Patterns ([string[]]$spec.Patterns)
            }
            catch {
                if ($GoFallbackPackages.ContainsKey($Tool)) {
                    Write-Warn "Release install failed for ${Tool}: $($_.Exception.Message). Trying go install fallback."
                    Install-GoTool -Tool $Tool -Package ([string]$GoFallbackPackages[$Tool])
                }
                else {
                    throw
                }
            }
        }
        else {
            throw "No installer is configured for $Tool."
        }

        $after = Test-DonzoTool -Tool $Tool
        if (-not $after.Available -and -not $DryRun) {
            throw "$Tool install command completed, but DONZO version check still fails: $($after.Error)"
        }
        Write-Ok "$Tool installed"
        return $true
    }
    catch {
        if ($RequiredForSelectedProfile) {
            throw
        }
        Write-Warn "Optional tool $Tool was not installed: $($_.Exception.Message)"
        return $false
    }
}

function Get-SelectedTools {
    if ($Profile -eq "all") {
        $required = @($RequiredByProfile.deep)
        $optional = @($OptionalByProfile.deep + $OptionalByProfile.normal + $OptionalByProfile.fast) | Select-Object -Unique
    }
    else {
        $required = @($RequiredByProfile[$Profile])
        $optional = @($OptionalByProfile[$Profile])
    }
    if ($RequiredOnly) {
        $optional = @()
    }
    $tools = @($required + $optional) | Select-Object -Unique
    return @{
        Required = $required
        Optional = $optional
        Tools = $tools
    }
}

function Invoke-DonzoPreflight {
    if ($DryRun) {
        Write-Info "Skipping DONZO preflight in dry-run mode"
        return
    }
    $checkProfile = if ($Profile -eq "all") { "deep" } else { $Profile }
    Write-Section "DONZO tool preflight"
    Push-Location $RepoRoot
    try {
        $env:PYTHONPATH = Join-Path $RepoRoot "src"
        [void](Invoke-External -File "python" -Arguments @("-m", "donzo", "tools", "check", "--profile", $checkProfile) -Required)
    }
    finally {
        Pop-Location
    }
}

Write-Section "DONZO installer"
Write-Info "Repository: $RepoRoot"
Write-Info "Profile: $Profile"
Write-Info "RequiredOnly: $RequiredOnly"
Write-Info "DryRun: $DryRun"

New-Directory -Path $ToolsRoot
New-Directory -Path $ToolsBin
Add-PathEntry -Path $ToolsBin
Add-PathEntry -Path $GoBin
Add-PathEntry -Path $PipxBin
Add-PathEntry -Path $PythonUserScripts

if (-not $SkipPrerequisites) {
    Write-Section "Prerequisites"
    Ensure-Python
    Ensure-Git
    Ensure-Go
    Ensure-Pipx
}
else {
    Write-Info "Skipping prerequisite installation"
}

Install-PythonProjectDeps

$selection = Get-SelectedTools
$requiredSet = @{}
foreach ($tool in $selection.Required) {
    $requiredSet[$tool] = $true
}

Write-Section "Selected tools"
Write-Info "Required: $($selection.Required -join ', ')"
if ($selection.Optional.Count -gt 0) {
    Write-Info "Optional: $($selection.Optional -join ', ')"
}

$failedOptional = @()
foreach ($tool in $selection.Tools) {
    $required = $requiredSet.ContainsKey($tool)
    $ok = Install-Tool -Tool $tool -RequiredForSelectedProfile:$required
    if (-not $ok -and -not $required) {
        $failedOptional += $tool
    }
}

Invoke-DonzoPreflight

Write-Section "Notes"
Write-Info "ProjectDiscovery httpx is installed into $GoBin so DONZO will prefer it over Python's httpx.exe."
Write-Info "gf patterns are user-managed; DONZO installs only the gf binary."
Write-Info "uncover requires provider keys before it can return useful data."
if ($failedOptional.Count -gt 0) {
    Write-Warn "Optional tools not installed: $($failedOptional -join ', ')"
}
Write-Ok "Installer completed"
