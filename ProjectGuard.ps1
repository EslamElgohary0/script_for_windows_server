<#
 ProjectGuard.ps1 - logs who deleted what inside a project folder and keeps the last version.
 Install   : .\ProjectGuard.ps1 -Mode Install   -ProjectPath D:\Projects\Alpha   (elevated PowerShell)
 Uninstall : .\ProjectGuard.ps1 -Mode Uninstall -ProjectPath D:\Projects\Alpha
 Run       : started automatically by the scheduled task (SYSTEM, at startup)
 Keep this file and dashboard.html in the same folder when installing.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Install','Run','Uninstall')][string]$Mode,
    [Parameter(Mandatory)][string]$ProjectPath,
    [string]$GuardName = '.guard'
)
$ErrorActionPreference = 'Stop'
$ProjectPath = (Resolve-Path -LiteralPath $ProjectPath).Path.TrimEnd('\')
$Guard   = Join-Path $ProjectPath $GuardName
$Vault   = Join-Path $Guard 'vault'      # mirror of the latest version of every file
$Deleted = Join-Path $Guard 'deleted'    # copies of deleted files, grouped by timestamp
$LogFile = Join-Path $Guard 'events.jsonl'
$DataJs  = Join-Path $Guard 'data.js'    # read by dashboard.html
$TaskName = 'ProjectGuard_' + ((Split-Path $ProjectPath -Leaf) -replace '[^\w]', '_')

function Rel($p)  { $p.Substring($ProjectPath.Length).TrimStart('\') }
function Skip($p) {
    $n = Split-Path $p -Leaf
    $p.StartsWith($Guard, [StringComparison]::OrdinalIgnoreCase) -or $n -like '~$*' -or $n -like '*.tmp'
}

function Write-GuardEvent($o) {
    ($o | ConvertTo-Json -Compress) | Add-Content -LiteralPath $LogFile -Encoding UTF8
    $all = @(Get-Content -LiteralPath $LogFile -Encoding UTF8 | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    'window.GUARD_DATA = ' + (ConvertTo-Json -InputObject $all -Compress -Depth 4) + ';' |
        Set-Content -LiteralPath $DataJs -Encoding UTF8
}

# Who deleted it? Look in the Security log (5145 = SMB share access, 4663 = local file access)
# for a DELETE request (access mask 0x10000) on the same file name just before now.
function Get-Who($full, $when) {
    $leaf = Split-Path $full -Leaf
    $r = [ordered]@{ user = 'Unknown'; ip = ''; machine = ''; source = 'Unknown'; app = '' }
    $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663, 5145; StartTime = $when.AddSeconds(-20); EndTime = $when.AddSeconds(15) } -ErrorAction SilentlyContinue
    $smb = $null; $loc = $null
    foreach ($e in $evs) {
        $d = @{}
        ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $mask = 0
        try { $mask = [Convert]::ToInt32(($d['AccessMask'] -replace '^0x', ''), 16) } catch {}
        if (-not ($mask -band 0x10000)) { continue }
        $name = if ($e.Id -eq 4663) { $d['ObjectName'] } else { $d['RelativeTargetName'] }
        if (-not $name -or -not $name.EndsWith($leaf, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($e.Id -eq 5145 -and -not $smb) { $smb = $d }
        if ($e.Id -eq 4663 -and -not $loc) { $loc = $d }
    }
    if ($smb) {
        $ip = $smb['IpAddress'] -replace '^::ffff:', ''
        $r.user = "$($smb['SubjectDomainName'])\$($smb['SubjectUserName'])"
        $r.ip = $ip; $r.source = 'SMB'
        try { $r.machine = ([Net.Dns]::GetHostEntry($ip)).HostName } catch { $r.machine = 'unresolved' }
    }
    elseif ($loc) {
        $r.user = "$($loc['SubjectDomainName'])\$($loc['SubjectUserName'])"
        $r.source = 'Local'; $r.machine = $env:COMPUTERNAME; $r.app = $loc['ProcessName']
    }
    $r
}

function Sync-File($p) {
    if (Skip $p) { return $true }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $true }
    $dst = Join-Path $Vault (Rel $p)
    New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
    try { Copy-Item -LiteralPath $p -Destination $dst -Force; return $true } catch { return $false }
}

function Handle-Delete($full, $when) {
    if (Skip $full) { return }
    $age = ((Get-Date) - $when).TotalSeconds     # $when = real time the deletion was detected
    if ($age -lt 2) { Start-Sleep -Seconds (2 - $age) }   # give the audit event time to be written
    if (Test-Path -LiteralPath $full) { return } # file is back = it was a replace/save, not a delete
    $rel = Rel $full
    $v = Join-Path $Vault $rel
    $who = Get-Who $full $when
    $stamp = $when.ToString('yyyyMMdd_HHmmss')
    $files = @()
    if (Test-Path -LiteralPath $v -PathType Container) { $files = @(Get-ChildItem -LiteralPath $v -Recurse -File) }
    elseif (Test-Path -LiteralPath $v -PathType Leaf)  { $files = @(Get-Item -LiteralPath $v) }
    $inFolder = Test-Path -LiteralPath $v -PathType Container

    if ($files.Count -eq 0) {   # never mirrored (created and deleted within seconds)
        Write-GuardEvent ([ordered]@{ time = $when.ToString('s'); file = $full; relative = $rel; sizeBytes = $null; sizeKB = $null; backup = ''
            user = $who.user; ip = $who.ip; machine = $who.machine; source = $who.source; app = $who.app; inFolder = $false })
        return
    }
    foreach ($f in $files) {
        $len = (Get-Item -LiteralPath $f.FullName).Length   # read the size BEFORE the move (after it the path no longer exists)
        $r = $f.FullName.Substring($Vault.Length).TrimStart('\')
        $dst = Join-Path (Join-Path $Deleted $stamp) $r
        New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
        Move-Item -LiteralPath $f.FullName -Destination $dst -Force
        Write-GuardEvent ([ordered]@{ time = $when.ToString('s'); file = (Join-Path $ProjectPath $r); relative = $r
            sizeBytes = $len; sizeKB = [math]::Round($len / 1KB, 1); backup = "deleted/$stamp/" + ($r -replace '\\', '/')
            user = $who.user; ip = $who.ip; machine = $who.machine; source = $who.source; app = $who.app; inFolder = $inFolder })
    }
    if ($inFolder) { Remove-Item -LiteralPath $v -Recurse -Force }
}

function Run-Guard {
    New-Item -ItemType Directory -Force $Vault, $Deleted | Out-Null
    if (-not (Test-Path $LogFile)) { New-Item $LogFile -ItemType File | Out-Null }
    $w = New-Object IO.FileSystemWatcher $ProjectPath
    $w.IncludeSubdirectories = $true
    $w.InternalBufferSize = 65536
    $w.NotifyFilter = 'FileName, DirectoryName, LastWrite, Size'
    foreach ($n in 'Created', 'Changed', 'Deleted', 'Renamed') { Register-ObjectEvent $w $n -SourceIdentifier "PG_$n" | Out-Null }
    $w.EnableRaisingEvents = $true
    robocopy $ProjectPath $Vault /E /XO /XD $Guard /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null   # initial mirror
    $pending = @{}
    while ($true) {
        $null = Wait-Event -Timeout 2
        foreach ($ev in @(Get-Event)) {
            $a = $ev.SourceEventArgs
            Remove-Event -EventIdentifier $ev.EventIdentifier
            switch ($ev.SourceIdentifier) {
                'PG_Created' { $pending[$a.FullPath] = Get-Date }
                'PG_Changed' { $pending[$a.FullPath] = Get-Date }
                'PG_Deleted' { try { Handle-Delete $a.FullPath $ev.TimeGenerated } catch { Add-Content (Join-Path $Guard 'errors.log') "$(Get-Date -f s) $_" } }
                'PG_Renamed' {
                    if (-not (Skip $a.FullPath) -and -not (Skip $a.OldFullPath)) {
                        $o = Join-Path $Vault (Rel $a.OldFullPath); $nw = Join-Path $Vault (Rel $a.FullPath)
                        if (Test-Path -LiteralPath $o) {
                            New-Item -ItemType Directory -Force (Split-Path $nw) | Out-Null
                            Move-Item -LiteralPath $o -Destination $nw -Force
                        }
                    }
                }
            }
        }
        foreach ($k in @($pending.Keys)) {          # debounce: copy 2s after the last change
            if (((Get-Date) - $pending[$k]).TotalSeconds -ge 2) { if (Sync-File $k) { $pending.Remove($k) } }
        }
    }
}

function Install-Guard {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
    if (-not $admin) { throw 'Run PowerShell as Administrator.' }
    if (-not (Test-Path (Join-Path $PSScriptRoot 'dashboard.html'))) { throw 'dashboard.html must be next to this script.' }

    New-Item -ItemType Directory -Force $Guard, $Vault, $Deleted | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'dashboard.html') $Guard -Force
    $self = Join-Path $Guard 'ProjectGuard.ps1'
    if ($PSCommandPath -ne $self) { Copy-Item $PSCommandPath $self -Force }
    'window.GUARD_DATA = [];' | Set-Content (Join-Path $Guard 'data.js') -Encoding UTF8

    # 1) turn on auditing (GUIDs = File System, Detailed File Share; works on any OS language)
    auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9244-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null

    # 2) audit rule (SACL) on the project folder: log every successful Delete
    $acl = Get-Acl -LiteralPath $ProjectPath -Audit
    $rule = New-Object Security.AccessControl.FileSystemAuditRule('Everyone', 'Delete,DeleteSubdirectoriesAndFiles', 'ContainerInherit,ObjectInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $ProjectPath -AclObject $acl

    # 3) lock the guard folder: only SYSTEM and Administrators, then hide it
    icacls $Guard /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    attrib +h +s $Guard

    # 4) scheduled task, runs as SYSTEM at startup, restarts on failure
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$self`" -Mode Run -ProjectPath `"$ProjectPath`""
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $trigger  = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Installed. Task: $TaskName  |  Dashboard: $Guard\dashboard.html" -ForegroundColor Green
}

function Uninstall-Guard {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Task removed. The $GuardName folder was kept (delete it manually if you no longer need the logs)."
}

switch ($Mode) {
    'Install'   { Install-Guard }
    'Run'       { Run-Guard }
    'Uninstall' { Uninstall-Guard }
}
