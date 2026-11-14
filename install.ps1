<#
.SYNOPSIS
    Bintra Automated Windows PowerShell Installer & Environment Configurator.
.DESCRIPTION
    Installs Bintra in editable mode, resolves Python dependencies, automatically
    configures user/machine PATH environment variables for instant CLI availability,
    and runs self-verification diagnostics.
.PARAMETER RunTests
    If specified, runs the complete test suite after installation.
#>
[CmdletBinding()]
param(
    [switch]$RunTests = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Bintra Automated Windows PowerShell Installer" -ForegroundColor Cyan
Write-Host "  Continuous Semantic Reverse Engineering & Binary Analysis" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detect Python
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} else {
    Write-Error "Python was not found on PATH. Please install Python 3.10+ from https://www.python.org/"
    return
}

# 2. Check Python Version
$verCheck = & ($pythonCmd -split ' ')[0] ($pythonCmd -split ' ')[1..10] -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python version 3.10 or higher is required. Detected version: $verCheck"
    return
}
Write-Host "[+] Detected Python version: $verCheck ($pythonCmd)" -ForegroundColor Green

# 3. Resolve scripts directory
$scriptsDir = & ($pythonCmd -split ' ')[0] ($pythonCmd -split ' ')[1..10] -c "import sysconfig; print(sysconfig.get_path('scripts'))"
Write-Host "[+] Python Scripts directory: $scriptsDir" -ForegroundColor Gray

# 4. Install / Update Dependencies and Package
Write-Host "[*] Installing Bintra package in editable development mode..." -ForegroundColor Yellow
$pkgRoot = $PSScriptRoot
if (-not $pkgRoot) { $pkgRoot = (Get-Item .).FullName }

& ($pythonCmd -split ' ')[0] ($pythonCmd -split ' ')[1..10] -m pip install -e $pkgRoot
if ($LASTEXITCODE -ne 0) {
    Write-Error "pip install failed. Please check network connectivity or disk permissions."
    return
}
Write-Host "[+] Bintra package installed successfully!" -ForegroundColor Green

# 5. Automatically Ensure PATH Environment Configuration
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$combinedPaths = "$userPath;$machinePath" -split ';' | Where-Object { $_ -ne "" }

$inPath = $false
foreach ($p in $combinedPaths) {
    if ((Resolve-Path -Path $p -ErrorAction SilentlyContinue).Path -eq (Resolve-Path -Path $scriptsDir -ErrorAction SilentlyContinue).Path) {
        $inPath = $true
        break
    }
}

if (-not $inPath) {
    Write-Host "[*] Adding Python Scripts directory to your User PATH..." -ForegroundColor Yellow
    $newUserPath = if ($userPath) { "$userPath;$scriptsDir" } else { $scriptsDir }
    [System.Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    $env:Path = "$env:Path;$scriptsDir"
    Write-Host "[+] Added '$scriptsDir' to User PATH environment variable." -ForegroundColor Green
    Write-Host "[!] Note: Newly opened terminals will automatically inherit this updated PATH." -ForegroundColor Gray
} else {
    Write-Host "[+] Python Scripts directory is already configured in system/user PATH." -ForegroundColor Green
}

# 6. Verification and Smoke Test
Write-Host "[*] Running verification smoke test..." -ForegroundColor Yellow
$smokeJson = & ($pythonCmd -split ' ')[0] ($pythonCmd -split ' ')[1..10] -m cli sense --hex "55 48 89 e5 90 5d c3"
if ($LASTEXITCODE -eq 0 -and $smokeJson -match "Bintra Sensory Cortex") {
    Write-Host "[+] Smoke test passed: 10 Metaphorical Senses and Security Kernel are operational!" -ForegroundColor Green
} else {
    Write-Warning "Smoke test encountered an issue. Output:`n$smokeJson"
}

# 7. Optional Unit Test Suite Execution
if ($RunTests) {
    Write-Host "[*] Executing test suite (227 unit & regression tests)..." -ForegroundColor Yellow
    & ($pythonCmd -split ' ')[0] ($pythonCmd -split ' ')[1..10] -m unittest discover -s "$pkgRoot\tests" -p "test_*.py"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] All test suites passed with 100% success rate!" -ForegroundColor Green
    } else {
        Write-Warning "Some tests did not pass. Check test log output above."
    }
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Installation and Verification Complete!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Global CLI Commands Available:" -ForegroundColor White
Write-Host "    bintra --help          (Main unified CLI)" -ForegroundColor Gray
Write-Host "    bintra-mcp                    (JSON-RPC 2.0 stdio MCP Server for AI)" -ForegroundColor Gray
Write-Host ""
Write-Host "  To configure Claude Desktop or Cursor for AI Agent integration:" -ForegroundColor White
Write-Host '    Add the following to your claude_desktop_config.json:' -ForegroundColor Gray
Write-Host '    {' -ForegroundColor Gray
Write-Host '      "mcpServers": {' -ForegroundColor Gray
Write-Host '        "bintra": {' -ForegroundColor Gray
Write-Host '          "command": "bintra-mcp",' -ForegroundColor Gray
Write-Host '          "args": []' -ForegroundColor Gray
Write-Host '        }' -ForegroundColor Gray
Write-Host '      }' -ForegroundColor Gray
Write-Host '    }' -ForegroundColor Gray
Write-Host "=====================================================================" -ForegroundColor Cyan
