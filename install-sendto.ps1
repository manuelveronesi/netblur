# SPDX-License-Identifier: Apache-2.0
# Adds the two netblur entries to the Windows "Send to" menu and removes entries left by older versions.
# Run once from the folder where you keep netblur:
#   powershell -ExecutionPolicy Bypass -File install-sendto.ps1

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sendTo = [Environment]::GetFolderPath('SendTo')
$shell = New-Object -ComObject WScript.Shell

foreach ($old in @('Mask passwords in configs', 'Mask passwords and personal data', 'Maschera password configurazioni')) {
    $stale = Join-Path $sendTo ($old + '.lnk')
    if (Test-Path $stale) { Remove-Item $stale -Force; Write-Host "Removed old entry: $old" }
}

$entries = @(
    @{ Name = 'netblur (secrets only)'; Target = 'run.bat'; Icon = 77 },
    @{ Name = 'netblur (secrets and personal data)'; Target = 'run_personal.bat'; Icon = 74 }
)
foreach ($e in $entries) {
    $link = $shell.CreateShortcut((Join-Path $sendTo ($e.Name + '.lnk')))
    $link.TargetPath = Join-Path $here $e.Target
    $link.WorkingDirectory = $here
    $link.IconLocation = "$env:SystemRoot\System32\imageres.dll,$($e.Icon)"
    $link.Save()
    Write-Host "Added to Send to: $($e.Name)"
}
