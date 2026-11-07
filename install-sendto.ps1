# SPDX-License-Identifier: Apache-2.0
# Adds the two mask-passwords entries to the Windows "Send to" menu.
# Run once from the repository folder:
#   powershell -ExecutionPolicy Bypass -File install-sendto.ps1

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sendTo = [Environment]::GetFolderPath('SendTo')
$shell = New-Object -ComObject WScript.Shell
$entries = @(
    @{ Name = 'Mask passwords in configs'; Target = 'run.bat'; Icon = 77 },
    @{ Name = 'Mask passwords and personal data'; Target = 'run_personal.bat'; Icon = 78 }
)
foreach ($e in $entries) {
    $link = $shell.CreateShortcut((Join-Path $sendTo ($e.Name + '.lnk')))
    $link.TargetPath = Join-Path $here $e.Target
    $link.WorkingDirectory = $here
    $link.IconLocation = "$env:SystemRoot\System32\imageres.dll,$($e.Icon)"
    $link.Save()
    Write-Host "Added to Send to: $($e.Name)"
}
