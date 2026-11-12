# The Windows side of tools/vm_test: asks the host for the next command,
# runs it as a PowerShell script block, and posts the output back.
# Started by one line in a PowerShell window (see vm_server.py). It runs as
# the signed-in user, with that user's rights, until its window is closed.
$ErrorActionPreference = 'Continue'
$base = '__BASE__'
$Host.UI.RawUI.WindowTitle = 'vm_test runner (close this window to stop it)'
Write-Host "vm_test runner: polling $base/next. Close this window to stop."
$work = Join-Path $env:USERPROFILE 'vm_test'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
while ($true) {
    try {
        $r = Invoke-WebRequest -Uri "$base/next" -UseBasicParsing -TimeoutSec 20
        if ($r.StatusCode -eq 200) {
            $cmd = $r.Content | ConvertFrom-Json
            Write-Host ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $cmd.id)
            $ok = $true
            try {
                $out = & ([scriptblock]::Create($cmd.ps)) 2>&1 | Out-String -Width 400
            } catch {
                $ok = $false
                $out = ($_ | Out-String)
            }
            $body = @{ id = $cmd.id; ok = $ok; output = $out } | ConvertTo-Json -Depth 3
            Invoke-WebRequest -Uri "$base/result/$($cmd.id)" -Method Put -UseBasicParsing `
                -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json' | Out-Null
        }
    } catch {
        Start-Sleep -Seconds 2
    }
    Start-Sleep -Milliseconds 700
}
