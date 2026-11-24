<#
.SYNOPSIS
  conn-audit.ps1 - audyt połączeń sieciowych Windows Server (odpowiednik conn-audit.sh).
  Bez agentów: tylko wbudowane cmdlety (Get-NetTCPConnection, CIM). Wymaga PowerShell 5.1+ i uprawnień Administratora.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\conn-audit.ps1 -DurationSeconds 604800

.PARAMETER IntervalSeconds
  Co ile sekund próbkować (domyślnie 5).

.PARAMETER DurationSeconds
  Łączny czas działania w sekundach (domyślnie 0 = do Ctrl+C lub pliku STOP).

.PARAMETER OutDir
  Katalog wyjściowy (domyślnie C:\ProgramData\conn-audit-<host>-<data>).

.PARAMETER IncludeLoopback
  Uwzględnij ruch loopback (domyślnie pomijany).

.PARAMETER ParseFirewallLog
  Dodatkowo czytaj na bieżąco log zapory Windows (pfirewall.log) i zapisuj conntrack.tsv: UDP (DNS, NTP, Kerberos...)
  oraz krótkie połączenia. Wymaga, by logowanie DOZWOLONYCH połączeń było już włączone (np. przez GPO).

.PARAMETER EnableFirewallLog
  Jak -ParseFirewallLog, ale skrypt sam włącza logowanie dozwolonych połączeń we wszystkich profilach
  i po zakończeniu przywraca poprzednie ustawienia. UWAGA: zmienia konfigurację zapory (GPO może to nadpisać).

.PARAMETER FirewallLogPath
  Ścieżka logu zapory (domyślnie ta z ustawień profilu, zwykle %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log).

.NOTES
Zatrzymanie: Ctrl+C albo utworzenie pustego pliku STOP w katalogu wyjściowym (dla uruchomienia w tle).
Wynik: info.txt, summary.tsv (+ conntrack.tsv z -ParseFirewallLog) - ten sam format co z Linuksa, więc conn-map.py łączy oba światy.
  IN  = ktoś łączy się DO tego serwera na lokalny port (port_lokalny)
  OUT = ten serwer łączy się DO kogoś (adres_zdalny:port_zdalny)
#>
[CmdletBinding()]
param(
    [int]$IntervalSeconds = 5,
    [int]$DurationSeconds = 0,
    [string]$OutDir = "",
    [switch]$IncludeLoopback,
    [switch]$ParseFirewallLog,
    [switch]$EnableFirewallLog,
    [string]$FirewallLogPath = ""
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Uruchom jako Administrator (potrzebne do nazw procesów i usług)."
    exit 1
}

$hostName = $env:COMPUTERNAME.ToLower()
if (-not $OutDir) {
    $OutDir = Join-Path $env:ProgramData ("conn-audit-{0}-{1}" -f $hostName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$SummaryPath = Join-Path $OutDir 'summary.tsv'
$InfoPath    = Join-Path $OutDir 'info.txt'
$StopFile    = Join-Path $OutDir 'STOP'

# UTF-8 BEZ BOM (conn-map.py czyta pierwszą linię nagłówka - BOM by ją zepsuł)
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Utf8([string]$Path, [string]$Text)  { [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom) }
function Append-Utf8([string]$Path, [string]$Text) { [System.IO.File]::AppendAllText($Path, $Text, $Utf8NoBom) }
function Format-Ip([string]$Ip) { ($Ip -replace '%.*$', '') -replace '^::ffff:', '' }

$fqdn = $hostName
if ($env:USERDNSDOMAIN) { $fqdn = "$hostName.$($env:USERDNSDOMAIN.ToLower())" }
$localIps = (Get-NetIPAddress -ErrorAction SilentlyContinue |
    ForEach-Object { Format-Ip $_.IPAddress } | Where-Object { $_ } | Sort-Object -Unique) -join ','
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
Write-Utf8 $InfoPath ("host: $fqdn`nstart: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')`ninterval: ${IntervalSeconds}s`nlokalne_ip: $localIps`nsystem: $os`n")

$CNT = @{}; $FIRST = @{}; $LAST = @{}; $MAXC = @{}; $PidInfo = @{}

# nazwa procesu + usługa Windows (np. svchost -> Dnscache) + wskazówka z linii poleceń (Java: -jar, Tomcat; IIS: pula aplikacji)
function Get-PidInfo([int]$ProcId) {
    if ($PidInfo.ContainsKey($ProcId)) { return $PidInfo[$ProcId] }
    $name = '-'; $unit = '-'; $hint = '?'
    if ($ProcId -gt 0) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
        if ($p) {
            $name = $p.Name -replace '\.exe$', ''
            $cmd = [string]$p.CommandLine
            $h = $null
            if     ($cmd -match '-jar\s+("[^"]+"|\S+)')                 { $h = '-jar ' + $Matches[1] }
            elseif ($cmd -match '-Dcatalina\.base=("[^"]+"|\S+)')       { $h = '-Dcatalina.base=' + $Matches[1] }
            elseif ($name -eq 'w3wp' -and $cmd -match '-ap\s+"([^"]+)"') { $h = 'pool:' + $Matches[1] }
            if (-not $h) { if ($cmd.Length -gt 80) { $h = $cmd.Substring(0, 80) } else { $h = $cmd } }
            $h = ($h -replace '[\t\r\n]', ' ').Trim()
            if ($h) { $hint = $h }
        }
        $svc = @(Get-CimInstance Win32_Service -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue)
        if ($svc.Count -gt 0) {
            $unit = ($svc | ForEach-Object { $_.Name }) -join '+'
            if ($unit.Length -gt 60) { $unit = $unit.Substring(0, 60) }
        }
    }
    $info = [pscustomobject]@{ Name = $name; Unit = $unit; Hint = $hint }
    $PidInfo[$ProcId] = $info
    return $info
}

function Invoke-Sample {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if ($conns.Count -eq 0) { return }
    $listen = @{}
    foreach ($c in $conns) {
        if ($c.State -eq 'Listen') { $listen[[int]$c.LocalPort] = [int]$c.OwningProcess }
    }
    $batch = @{}
    foreach ($c in $conns) {
        if ($c.State -eq 'Listen' -or $c.State -eq 'Bound') { continue }
        $rip = Format-Ip $c.RemoteAddress
        if (-not $rip -or $rip -eq '0.0.0.0' -or $rip -eq '::') { continue }
        if (-not $IncludeLoopback -and ($rip -like '127.*' -or $rip -eq '::1')) { continue }
        $lport = [int]$c.LocalPort
        $procId = [int]$c.OwningProcess
        if ($listen.ContainsKey($lport)) { $dir = 'IN' } else { $dir = 'OUT' }
        if ($procId -eq 0 -and $dir -eq 'IN') { $procId = $listen[$lport] }   # TimeWait nie ma PID - bierzemy proces nasłuchujący
        $info = Get-PidInfo $procId
        if ($dir -eq 'IN') { $lp = [string]$lport; $rp = '-' } else { $lp = '-'; $rp = [string]$c.RemotePort }
        $key = (@($dir, 'tcp', $lp, $rip, $rp, $info.Name, $info.Unit, $info.Hint) -join "`t")
        if ($batch.ContainsKey($key)) { $batch[$key]++ } else { $batch[$key] = 1 }
    }
    foreach ($k in @($batch.Keys)) {
        $n = $batch[$k]
        if (-not $CNT.ContainsKey($k)) { $CNT[$k] = 0; $MAXC[$k] = 0; $FIRST[$k] = $ts }
        $CNT[$k] = $CNT[$k] + 1
        $LAST[$k] = $ts
        if ($n -gt $MAXC[$k]) { $MAXC[$k] = $n }
    }
}

function Save-Summary {
    $header = "kierunek`tproto`tport_lokalny`tadres_zdalny`tport_zdalny`tproces`tjednostka`tkomenda`tprobek`tmax_jednoczesnych`tpierwszy`tostatni"
    $rows = foreach ($k in @($CNT.Keys)) {
        $f = $k -split "`t"
        [pscustomobject]@{
            Dir = $f[0]; Rip = $f[3]
            LP  = [int]($f[2] -replace '^-$', '0')
            RP  = [int]($f[4] -replace '^-$', '0')
            Line = "$k`t$($CNT[$k])`t$($MAXC[$k])`t$($FIRST[$k])`t$($LAST[$k])"
        }
    }
    $lines = @($rows | Sort-Object Dir, LP, RP, Rip | ForEach-Object { $_.Line })
    $text = $header + "`n"
    if ($lines.Count -gt 0) { $text += ($lines -join "`n") + "`n" }
    Write-Utf8 "$SummaryPath.tmp" $text
    Move-Item -Force "$SummaryPath.tmp" $SummaryPath
}

# ---------- opcjonalnie: log zapory Windows -> conntrack.tsv (UDP i krótkie połączenia; odpowiednik conntrack z Linuksa) ----------
$useFw = ($ParseFirewallLog -or $EnableFirewallLog)
$FwSaved = $null; $FwOffset = 0; $FwIdx = @{}
$FwCnt = @{}; $FwFirst = @{}; $FwLast = @{}
$ConntrackPath = Join-Path $OutDir 'conntrack.tsv'

function Read-LogText([string]$Path, [long]$Offset, [long]$Max = 16777216) {
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($Offset -gt $fs.Length) { return '' }
        [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $n = [int][Math]::Min($Max, [long]($fs.Length - $Offset))
        $buf = New-Object byte[] $n
        $read = $fs.Read($buf, 0, $n)
        return [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)    # ASCII: 1 bajt = 1 znak, więc offset w znakach = offset w bajtach
    } catch { return '' } finally { if ($fs) { $fs.Dispose() } }
}

function Add-FwLines([string]$Text) {
    $ix = $script:FwIdx
    if (-not $ix.ContainsKey('path')) { return }
    $need = $ix['path']
    foreach ($line in $Text.Split("`n")) {
        if ($line.Length -lt 20 -or $line[0] -eq '#') { continue }
        $f = $line.TrimEnd("`r").Split(' ')
        if ($f.Length -le $need) { continue }
        $act = $f[$ix['action']]
        if ($act -ne 'ALLOW' -and $act -ne 'OPEN' -and $act -ne 'OPEN-INBOUND') { continue }   # DROP/CLOSE pomijamy
        $proto = $f[$ix['protocol']].ToLower()
        if ($proto -ne 'tcp' -and $proto -ne 'udp' -and $proto -ne 'icmp') { continue }
        $src = Format-Ip $f[$ix['src-ip']]; $dst = Format-Ip $f[$ix['dst-ip']]
        $dp = $f[$ix['dst-port']]
        if ($f[$need] -eq 'SEND')         { $dir = 'OUT'; $rip = $dst; $lp = '-';  $rp = $dp }
        elseif ($f[$need] -eq 'RECEIVE')  { $dir = 'IN';  $rip = $src; $lp = $dp;  $rp = '-' }
        else { continue }
        if (-not $rip -or $rip -eq '-') { continue }
        # szum: loopback, link-local, multicast, broadcast
        if ($rip -match '^(127\.|169\.254\.|22[4-9]\.|23[0-9]\.|255\.255\.255\.255$)' -or $rip -eq '::1' -or $rip -match '^(fe80:|ff[0-9a-f][0-9a-f]:)') { continue }
        $name = '-'; $unit = '-'
        if ($ix.ContainsKey('pid') -and $f.Length -gt $ix['pid']) {
            $pv = 0
            if ([int]::TryParse($f[$ix['pid']], [ref]$pv) -and $pv -gt 0) { $pinfo = Get-PidInfo $pv; $name = $pinfo.Name; $unit = $pinfo.Unit }
        }
        $key = (@($dir, $proto, $lp, $rip, $rp, $name, $unit) -join "`t")
        $ts = $f[0] + ' ' + $f[1]
        if (-not $script:FwCnt.ContainsKey($key)) { $script:FwCnt[$key] = 0; $script:FwFirst[$key] = $ts }
        $script:FwCnt[$key] = $script:FwCnt[$key] + 1
        $script:FwLast[$key] = $ts
    }
}

function Read-FwLog {
    if (-not (Test-Path -LiteralPath $FirewallLogPath)) { return }
    $len = (Get-Item -LiteralPath $FirewallLogPath).Length
    if ($script:FwOffset -gt $len) {      # rotacja logu: doczytaj ogon z pliku .old, potem czytaj nowy od początku
        $old = "$FirewallLogPath.old"
        if (Test-Path -LiteralPath $old) { Add-FwLines (Read-LogText $old $script:FwOffset) }
        $script:FwOffset = 0
    }
    $text = Read-LogText $FirewallLogPath $script:FwOffset
    if (-not $text) { return }
    $last = $text.LastIndexOf("`n")
    if ($last -lt 0) { return }            # niepełna linia - doczytamy w następnej próbce
    $script:FwOffset += ($last + 1)
    Add-FwLines $text.Substring(0, $last + 1)
}

function Save-Conntrack {
    $header = "kierunek`tproto`tport_lokalny`tadres_zdalny`tport_zdalny`tproces`tjednostka`tnowych`tpierwszy`tostatni"
    $rows = foreach ($k in @($FwCnt.Keys)) {
        $f = $k -split "`t"
        [pscustomobject]@{
            Dir = $f[0]; Rip = $f[3]
            LP  = [int]($f[2] -replace '^-$', '0'); RP = [int]($f[4] -replace '^-$', '0')
            Line = "$k`t$($FwCnt[$k])`t$($FwFirst[$k])`t$($FwLast[$k])"
        }
    }
    $lines = @($rows | Sort-Object Dir, LP, RP, Rip | ForEach-Object { $_.Line })
    $text = $header + "`n"
    if ($lines.Count -gt 0) { $text += ($lines -join "`n") + "`n" }
    Write-Utf8 "$ConntrackPath.tmp" $text
    Move-Item -Force "$ConntrackPath.tmp" $ConntrackPath
}

if ($EnableFirewallLog) {
    if (-not $FirewallLogPath) { $FirewallLogPath = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log' }
    $FwSaved = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Select-Object Name, LogAllowed, LogFileName, LogMaxSizeKilobytes)
    try {
        Set-NetFirewallProfile -Profile Domain, Private, Public -LogAllowed True -LogFileName $FirewallLogPath -LogMaxSizeKilobytes 32767 -ErrorAction Stop
        Write-Host "Włączono logowanie dozwolonych połączeń w zaporze (po audycie zostanie przywrócone poprzednie ustawienie)."
    } catch {
        Write-Warning "Nie udało się włączyć logu zapory (GPO?): $($_.Exception.Message). Włącz go przez GPO i użyj -ParseFirewallLog."
        $FwSaved = $null
    }
}
if ($useFw) {
    if (-not $FirewallLogPath) {
        $fn = (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' } | Select-Object -First 1).LogFileName
        if ($fn -and $fn -ne 'NotConfigured') { $FirewallLogPath = [Environment]::ExpandEnvironmentVariables($fn) }
        else { $FirewallLogPath = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log' }
    }
    $notLogging = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.LogAllowed -ne 'True' })
    if ($notLogging.Count -gt 0) {
        Write-Warning ("Logowanie dozwolonych połączeń jest wyłączone w profilach: " + (($notLogging | ForEach-Object { $_.Name }) -join ', ') + ". conntrack.tsv będzie pusty (włącz przez GPO albo użyj -EnableFirewallLog).")
    }
    if (Test-Path -LiteralPath $FirewallLogPath) { $FwOffset = (Get-Item -LiteralPath $FirewallLogPath).Length } else { $FwOffset = 0 }   # liczymy tylko to, co powstanie po starcie audytu
    $FwIdx = @{ 'action' = 2; 'protocol' = 3; 'src-ip' = 4; 'dst-ip' = 5; 'src-port' = 6; 'dst-port' = 7; 'path' = 16; 'pid' = 17 }
    foreach ($l in ((Read-LogText $FirewallLogPath 0 8192) -split "`n")) {
        if ($l.StartsWith('#Fields:')) {
            $fn2 = ($l.Substring(8).Trim()) -split '\s+'
            $FwIdx = @{}
            for ($i = 0; $i -lt $fn2.Count; $i++) { $FwIdx[$fn2[$i]] = $i }
            break
        }
    }
    Append-Utf8 $InfoPath ("firewall_log: $FirewallLogPath`n")
    Save-Conntrack
}

$start = Get-Date; $lastDump = Get-Date
Write-Host "Start audytu -> $OutDir (Ctrl+C lub utworzenie pliku STOP kończy i zapisuje wynik)"
try {
    while ($true) {
        Invoke-Sample
        if ($useFw) { Read-FwLog }
        if (((Get-Date) - $lastDump).TotalSeconds -ge 60) { Save-Summary; if ($useFw) { Save-Conntrack }; $lastDump = Get-Date }
        if ($DurationSeconds -gt 0 -and ((Get-Date) - $start).TotalSeconds -ge $DurationSeconds) { break }
        if (Test-Path $StopFile) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
}
finally {
    if ($useFw) { Read-FwLog; Save-Conntrack }
    if ($FwSaved) {
        foreach ($p in $FwSaved) {
            $restore = @{ Name = $p.Name; LogAllowed = $p.LogAllowed }
            if ($p.LogFileName -and "$($p.LogFileName)" -ne 'NotConfigured') { $restore.LogFileName = $p.LogFileName }
            if ($p.LogMaxSizeKilobytes -and "$($p.LogMaxSizeKilobytes)" -ne 'NotConfigured') { $restore.LogMaxSizeKilobytes = $p.LogMaxSizeKilobytes }
            Set-NetFirewallProfile @restore -ErrorAction SilentlyContinue
        }
        Write-Host "Przywrócono poprzednie ustawienia logowania zapory."
    }
    Save-Summary
    Append-Utf8 $InfoPath ("stop: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')`n")
    Remove-Item $StopFile -ErrorAction SilentlyContinue
    Write-Host "Gotowe. Wyniki: $OutDir"
}
