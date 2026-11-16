# SPDX-License-Identifier: Apache-2.0
# Adds the two netblur entries to the Windows "Send to" menu and removes entries left by older versions.
# Run once from the folder where you keep netblur:
#   powershell -ExecutionPolicy Bypass -File install-sendto.ps1
# The entries open the netblur window with the report. Add -Console to get the classic console
# window instead (run.bat and run_personal.bat); that is also the fallback when pyw is not found.
param([switch]$Console)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sendTo = [Environment]::GetFolderPath('SendTo')
$shell = New-Object -ComObject WScript.Shell

foreach ($old in @('Mask passwords in configs', 'Mask passwords and personal data', 'Maschera password configurazioni')) {
    $stale = Join-Path $sendTo ($old + '.lnk')
    if (Test-Path $stale) { Remove-Item $stale -Force; Write-Host "Removed old entry: $old" }
}

$pyw = $null
if (-not $Console) {
    foreach ($name in 'pyw', 'pythonw') {
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { $pyw = $cmd.Source; break }
    }
    if (-not $pyw) { Write-Host 'pyw not found: the entries will use the console window.' }
}

$entries = @(
    @{ Name = 'netblur (secrets only)'; Batch = 'run.bat'; Option = ''; Icon = 77 },
    @{ Name = 'netblur (secrets and personal data)'; Batch = 'run_personal.bat'; Option = ' --personal'; Icon = 74 }
)
foreach ($e in $entries) {
    $link = $shell.CreateShortcut((Join-Path $sendTo ($e.Name + '.lnk')))
    if ($pyw) {
        # Windowless Python: only the netblur window appears. Send to appends the selected files.
        $link.TargetPath = $pyw
        $link.Arguments = '"' + (Join-Path $here 'netblur.py') + '" --gui' + $e.Option
    } else {
        $link.TargetPath = Join-Path $here $e.Batch
        $link.Arguments = ''
    }
    $link.WorkingDirectory = $here
    $link.IconLocation = "$env:SystemRoot\System32\imageres.dll,$($e.Icon)"
    $link.Save()
    Write-Host "Added to Send to: $($e.Name)"
}
