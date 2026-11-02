<#
.SYNOPSIS
  GUI smoke test of the published EXE (adapted from project A). Runs it twice with --smoke-test:
  1) real sensors + this machine's real event logs + the virtual demo scenario (--demo-data),
  2) mock sensors + real event logs, no demo data.
  Each run drives every screen and the main commands, saves screenshots and a JSON report, and must exit with 0.
#>
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$ReportDir = "dist/smoke"
)
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
$ReportDir = (Resolve-Path $ReportDir).Path
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$failures = @()
foreach ($mode in @('real-demo', 'mock')) {
    $out = Join-Path $ReportDir $mode
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $data = Join-Path $temp "wdl-gui-smoke-$mode-$(Get-Random)"
    $arguments = @('--smoke-test', '--data-dir', $data, '--smoke-report', $out, '--history-days', '7')
    if ($mode -eq 'real-demo') { $arguments += '--demo-data' } else { $arguments += '--mock-sensors' }
    Write-Host "Running GUI smoke test ($mode)..."
    $process = Start-Process -FilePath $exePath -ArgumentList $arguments -PassThru
    $null = $process.Handle  # keeps the exit code available after exit
    if (-not $process.WaitForExit(420000)) {
        Stop-Process -Id $process.Id -Force
        $failures += "${mode}: timed out"
        continue
    }

    $report = Join-Path $out 'smoke-report.json'
    if (Test-Path $report) { Get-Content $report -Raw -Encoding utf8 | Write-Host } else { $failures += "${mode}: no report written" }
    $logs = Join-Path $data 'logs'
    if (Test-Path $logs) { Copy-Item -Recurse $logs (Join-Path $out 'logs') }
    if ($process.ExitCode -ne 0) { $failures += "${mode}: exit code $($process.ExitCode)" }
}

if ($failures.Count -gt 0) { throw "GUI smoke test failed: $($failures -join '; ')" }
Write-Host 'GUI smoke test OK (real logs with demo data, and mock sensors).'
