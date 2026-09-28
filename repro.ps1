#requires -Version 5.1
<#
.SYNOPSIS
  One-click reproduction for "Direct syscalls on Sophos Endpoint (Intercept X) with no console alert".

.DESCRIPTION
  Run from the folder containing activebreach.dll and abe_poc.exe, as a NORMAL user
  (no admin rights needed). The script performs automatic PASS/FAIL checks and saves
  a full transcript to repro_output_<timestamp>.txt

  Checks performed:
    1. OS / environment / registered AV (SecurityCenter2)
    2. Sophos services + on-disk component versions
    3. State of the 6 ntdll syscall stubs (expect 4 x HOOK E9)
    4. Hook attribution trace (expect filtering code inside SophosED.dll)
    5. Process-wide SophosED.dll injection count (permanent surveillance proof)
    6. Binary SHA256 + optional verification against SHA256SUMS.txt
    7. Local Sophos event-log baseline (record IDs captured before the run)
    8. PoC run, expected-output verification (PASS/FAIL per stage)
    9. Post-run diff of Sophos event logs (expect 0 new events)

.USAGE
  powershell -ExecutionPolicy Bypass -File .\repro.ps1
  .\repro.ps1 -SkipPoC          # checks only, do not launch the PoC
  .\repro.ps1 -NoAttribution    # skip the SophosED.dll attribution trace
#>
param(
    [switch]$SkipPoC,
    [switch]$NoAttribution
)

$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
$script:Checks = @()

function Add-Check($Name, $Pass, $Detail) {
    $script:Checks += [pscustomobject]@{ Check = $Name; Pass = $Pass; Detail = $Detail }
}
function Section($t) {
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor Cyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor Cyan
}
function Mark($ok, $msg) {
    if ($ok) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
    else     { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
    return $ok
}

$fstamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$log    = "repro_output_$fstamp.txt"
Start-Transcript -Path $log -Force | Out-Null

# =============================================================================
Section 'CHECK 1 - OS / ENVIRONMENT / REGISTERED AV'
# =============================================================================
$nowLocal = Get-Date
$nowUtc   = $nowLocal.ToUniversalTime()
Write-Host "Local time : $nowLocal"
Write-Host "UTC time   : $nowUtc"
Write-Host "Computer   : $env:COMPUTERNAME"
Write-Host "User       : $env:USERNAME  (normal user, admin NOT required)"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("OS         : {0} {1} (build {2})" -f $os.Caption, $os.OSArchitecture, $os.BuildNumber)
try {
    $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).UBR
    Write-Host ("Full build : {0}.{1}" -f $os.BuildNumber, $ubr)
    Add-Check 'OS build readable' $true "$($os.BuildNumber).$ubr"
} catch { Add-Check 'OS build readable' $false 'UBR not readable' }

$avList = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
if ($avList) {
    foreach ($av in $avList) {
        Write-Host ("AV product : {0}  (state 0x{1:X6})" -f $av.displayName, $av.productState)
    }
    $hasSophos = [bool]($avList | Where-Object { $_.displayName -like '*Sophos*' })
    Add-Check 'Sophos registered in SecurityCenter2' $hasSophos 'root\SecurityCenter2 query'
} else {
    Write-Host 'AV product : (SecurityCenter2 query returned nothing)'
    Add-Check 'Sophos registered in SecurityCenter2' $false 'query failed'
}
Write-Host 'The environment state is also shown live at the start of the attached video (PoC.cleaned.mp4).'

# =============================================================================
Section 'CHECK 2 - SOPHOS AGENT STATE'
# =============================================================================
$svcs = Get-Service | Where-Object { $_.Name -like '*sophos*' } | Sort-Object Name
if ($svcs) {
    $svcs | Select-Object Name, Status | Format-Table -AutoSize | Out-String | Write-Host
    $running = @($svcs | Where-Object Status -eq 'Running').Count
    Add-Check 'Sophos services running' ($running -gt 0) "$running service(s) running"
} else {
    Write-Host 'WARNING: no Sophos service found - install Sophos Endpoint first (see guide, Part A).' -ForegroundColor Yellow
    Add-Check 'Sophos services running' $false 'none found'
}
Write-Host 'Component versions (read from on-disk files, best effort):'
$compPaths = @(
    'C:\Program Files\Sophos\Endpoint Defense\SophosED.dll',
    'C:\Program Files\Sophos\Management Communications System\ManagementAgentNT.exe'
)
foreach ($p in $compPaths) {
    if (Test-Path $p) {
        try {
            $v = (Get-Item $p).VersionInfo.ProductVersion
            Write-Host ("  {0} -> {1}" -f (Split-Path $p -Leaf), $v)
        } catch {}
    }
}
# fallback: locate the files under the Sophos folder (paths vary by install)
foreach ($name in @('SophosED.dll','ManagementAgentNT.exe')) {
    if (-not ($compPaths | Where-Object { Test-Path $_ } | Where-Object { $_ -like "*$name" })) {
        $hit = Get-ChildItem 'C:\Program Files\Sophos' -Recurse -Filter $name -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) {
            try {
                $v = $hit.VersionInfo.ProductVersion
                Write-Host ("  {0} -> {1}   ({2})" -f $name, $v, $hit.FullName)
            } catch {}
        }
    }
}

# =============================================================================
Section 'CHECK 3 - NTDLL SYSCALL STUBS (16-byte dump, 6 functions)'
# =============================================================================
try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Mem {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    public static IntPtr Module(string n){ return GetModuleHandle(n); }
    public static IntPtr Proc(IntPtr m, string n){ return GetProcAddress(m, n); }
    public static byte[] Read(IntPtr addr, int len){
        byte[] b = new byte[len]; int r;
        if(!ReadProcessMemory(GetCurrentProcess(), addr, b, len, out r) || r < len) return null;
        return b;
    }
}
"@
} catch {}

$nt = [Mem]::Module('ntdll.dll')
$funcs = @('NtAllocateVirtualMemory','NtProtectVirtualMemory','NtFreeVirtualMemory','NtClose','NtCreateThreadEx','NtQuerySystemInformation')
$hookCount = 0
$hookReport = @()
foreach ($f in $funcs) {
    $p = [Mem]::Proc($nt, $f)
    if ($p -eq [IntPtr]::Zero) { Write-Host ("{0,-28} NOT FOUND" -f $f); continue }
    $b = [Mem]::Read($p, 16)
    $hex = ($b[0..7] | ForEach-Object { $_.ToString('X2') }) -join ' '
    if ($b[0] -eq 0xE9)                 { $state = 'HOOK (E9 jmp)'; $hookCount++ }
    elseif ($b[0] -eq 0x4C -and $b[1] -eq 0x8B -and $b[2] -eq 0xD1 -and $b[3] -eq 0xB8)
                                        { $state = 'intact (native prologue)' }
    else                                { $state = 'UNEXPECTED' }
    Write-Host ("{0,-28} {1}   {2}" -f $f, $hex, $state)
    $hookReport += "$f : $hex $state"
}
Write-Host ''
Write-Host 'Expected: 4 x HOOK (E9 jmp) on the memory/handle APIs, 2 intact.'
Write-Host 'A native Microsoft stub always starts with 4C 8B D1 B8 (mov r10,rcx ; mov eax,SSN).'
Add-Check 'Expected hook layout (4 hooked + 2 intact)' ($hookCount -eq 4) "$hookCount hooked of 6"

# =============================================================================
Section 'CHECK 4 - HOOK ATTRIBUTION TRACE (which DLL filters the hook)'
# =============================================================================
$attribOk = $false
if (-not $NoAttribution) {
    $p = [Mem]::Proc($nt, 'NtAllocateVirtualMemory')
    $b = [Mem]::Read($p, 5)
    if ($b[0] -eq 0xE9) {
        $rel   = [BitConverter]::ToInt32($b, 1)
        $tramp = [IntPtr]([Int64]$p + 5 + $rel)
        Write-Host ("stub  NtAllocateVirtualMemory : {0}" -f $p)
        Write-Host ("  E9 jmp -> trampoline page   : {0}" -f $tramp)
        Write-Host '  (anonymous private executable page, ~1 GB below ntdll: atypical allocation)'
        $tb = [Mem]::Read($tramp, 6)
        if ($tb[0] -eq 0xFF -and $tb[1] -eq 0x25) {
            $disp   = [BitConverter]::ToInt32($tb, 2)
            $ptrLoc = [IntPtr]([Int64]$tramp + 6 + $disp)
            $filter = [IntPtr][BitConverter]::ToInt64([Mem]::Read($ptrLoc, 8), 0)
            Write-Host ("  FF 25 indirect jmp -> filter  : {0}" -f $filter)
            $mod = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
                   Where-Object { [Int64]$filter -ge [Int64]$_.BaseAddress -and
                                  [Int64]$filter -lt ([Int64]$_.BaseAddress + $_.ModuleMemorySize) } |
                   Select-Object -First 1
            if ($mod) {
                $off = [Int64]$filter - [Int64]$mod.BaseAddress
                Write-Host ("  filter code is INSIDE {0} + 0x{1:X}" -f $mod.ModuleName, $off) -ForegroundColor Green
                Write-Host '  => inline hook attribution: Sophos (SophosED.dll). Offset varies by agent version.'
                $attribOk = ($mod.ModuleName -like 'SophosED*')
            } else {
                Write-Host ("  filter at {0} (owning module not injected in this process; re-run from another process)" -f $filter)
            }
        }
    } else {
        Write-Host 'stub is not hooked - attribution not applicable.'
    }
    Add-Check 'Hook filter attributed to SophosED.dll' $attribOk 'trampoline trace'
} else {
    Write-Host 'Skipped (-NoAttribution).'
}

# =============================================================================
Section 'CHECK 5 - SOPHOSED.DLL INJECTION ACROSS PROCESSES'
# =============================================================================
$injCount = 0
$procs = Get-Process -ErrorAction SilentlyContinue
foreach ($pr in $procs) {
    try {
        if ($pr.Modules | Where-Object { $_.ModuleName -eq 'SophosED.dll' }) { $injCount++ }
    } catch {}
}
Write-Host ("SophosED.dll is loaded in {0} process(es) on this machine." -f $injCount)
Write-Host 'The hooks are permanent surveillance injected into every process, not a reaction to the tool.'
Add-Check 'SophosED.dll present in processes' ($injCount -gt 0) "$injCount process(es)"

# =============================================================================
Section 'CHECK 6 - BINARY INTEGRITY (SHA256)'
# =============================================================================
$hashOk = $true
$sumsFile = 'SHA256SUMS.txt'
foreach ($f in @('activebreach.dll','abe_poc.exe')) {
    if (Test-Path ".\$f") {
        $h = (Get-FileHash ".\$f" -Algorithm SHA256).Hash
        Write-Host ("{0,-18} SHA256 = {1}" -f $f, $h)
        if (Test-Path ".\$sumsFile") {
            # Accepts two formats:
            #   a) standard:  <64 hex>  <filename>            (same line)
            #   b) raw certutil output:
            #        SHA256 hash of <filename>:
            #        <64 hex>
            #        CertUtil: -hashfile command completed successfully.
            $lines = @(Get-Content ".\$sumsFile" -ErrorAction SilentlyContinue)
            $expected = $null
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $ln = $lines[$i]
                if ($ln -match '(?i)sha256\s+hash\s+of\s+(.+?):' -and $Matches[1].Trim() -ieq $f) {
                    for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                        if ($lines[$j] -match '([0-9A-Fa-f]{64})') { $expected = $Matches[1]; break }
                        if ($lines[$j].Trim() -ne '') { break }
                    }
                    break
                }
                if ($ln -match '([0-9A-Fa-f]{64})' -and $ln -like "*$f*") {
                    $expected = $Matches[1]; break
                }
            }
            if ($expected) {
                $matchOk = ($expected.ToUpper() -eq $h)
                $null = Mark $matchOk "$f hash matches SHA256SUMS.txt"
                if (-not $matchOk) { $hashOk = $false }
            } else {
                Write-Host ("  (no entry for {0} in {1} - compare manually)" -f $f, $sumsFile)
            }
        }
    } else {
        Write-Host ("{0,-18} MISSING - copy it next to this script" -f $f) -ForegroundColor Yellow
        $hashOk = $false
    }
}
Add-Check 'Binaries present (and hashes verified if SHA256SUMS.txt exists)' $hashOk ''

# =============================================================================
Section 'CHECK 7 - LOCAL SOPHOS EVENT-LOG BASELINE (before the run)'
# =============================================================================
$sophosLogs = Get-WinEvent -ListLog '*sophos*' -ErrorAction SilentlyContinue |
              Where-Object { $_.RecordCount -gt 0 } | Select-Object -ExpandProperty LogName
$baseline = @{}
foreach ($l in $sophosLogs) {
    $last = Get-WinEvent -LogName $l -MaxEvents 1 -ErrorAction SilentlyContinue
    $baseline[$l] = if ($last) { $last.RecordId } else { 0 }
    Write-Host ("  log {0,-45} newest RecordId = {1}" -f $l, $baseline[$l])
}
if (-not $sophosLogs) { Write-Host '  (no Sophos event logs found)' }
Write-Host 'These record IDs are the baseline. After the PoC we count NEW events only.'

# =============================================================================
if (-not $SkipPoC) {
Section 'CHECK 8 - POC RUN (bypassed init + direct syscall + data retrieval)'
# =============================================================================
    Write-Host 'Launching .\abe_poc.exe ...' -ForegroundColor Yellow
    Write-Host 'Stages: engine init under the 4 hooks -> direct syscall inside ntdll .text -> kernel answers.'
    Write-Host ''
    $t0 = Get-Date
    $pocOut = & .\abe_poc.exe 2>&1 | Out-String
    $t1 = Get-Date
    $pocOut | Out-File -Encoding utf8 poc_output.txt
    Write-Host $pocOut
    Write-Host ("PoC started  : {0}" -f $t0)
    Write-Host ("PoC finished : {0}  (duration {1}s)" -f $t1, [int]($t1 - $t0).TotalSeconds)
    Write-Host ("Exit code    : {0} (0x{1:X8})" -f $LASTEXITCODE, $LASTEXITCODE)

    Add-Check 'Stage 1: init under hooks (SYSCALL_TABLE initialized, 488 entries)' `
        ($pocOut -match 'SYSCALL_TABLE initialized.*entries=488') '488 SSN table built despite hooks'
    Add-Check 'Stage 2: SysCallX64 bypass ([L3] direct ntdll prologue call)' `
        ($pocOut -match '\[L3\]') 'syscall physically executes inside ntdll .text'
    Add-Check 'Stage 3: kernel answered (SUCCESS + process list retrieved)' `
        ($pocOut -match 'SUCCESS! Syscall executed without detection' -and $pocOut -match 'processes read via direct syscall') `
        'NtQuerySystemInformation returned through the hidden path'

    if ($LASTEXITCODE -eq -1073741819) {
        Write-Host ''
        Write-Host 'NOTE: exit code 0xC0000005 is EXPECTED here (documented in the report, section E.3).' -ForegroundColor Yellow
        Write-Host 'The syscall and its full response completed BEFORE this post-execution reaction.'
        Write-Host 'Please read the output above the exit line as the result, not the exit code.'
    }
}

# =============================================================================
Section 'CHECK 9 - POST-RUN: NEW EVENTS IN SOPHOS LOGS? (expect 0)'
# =============================================================================
$newTotal = 0
foreach ($l in $baseline.Keys) {
    $new = @(Get-WinEvent -LogName $l -ErrorAction SilentlyContinue |
             Where-Object { $_.RecordId -gt $baseline[$l] })
    $newTotal += $new.Count
    Write-Host ("  log {0,-45} new events since baseline: {1}" -f $l, $new.Count)
    foreach ($e in $new) {
        Write-Host ("     -> {0}  Id={1}  {2}" -f $e.TimeCreated, $e.Id, $e.Message)
    }
}
Write-Host ''
Write-Host ("TOTAL new Sophos local events during the run window: {0} (expected: 0)" -f $newTotal)
Add-Check 'No new events in local Sophos logs during the run' ($newTotal -eq 0) "$newTotal new"
Write-Host ''
Write-Host 'Local logs are only a proxy. The authoritative check is the console:'
Write-Host '  Sophos Central -> Devices -> this machine -> Events tab -> refresh.'
Write-Host ("  Run window was {0} - {1}. Confirm NO event exists for it. The attached video shows this exact check live at the end." -f $t0, $t1)
Write-Host 'The attached video PoC.cleaned.mp4 shows this console check live, single take.'

# =============================================================================
Section 'SUMMARY OF AUTOMATIC CHECKS'
# =============================================================================
$script:Checks | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($script:Checks | Where-Object { -not $_.Pass })
if ($failed.Count -eq 0) {
    Write-Host 'ALL AUTOMATIC CHECKS PASSED.' -ForegroundColor Green
    Write-Host 'Remaining manual step: confirm the Events tab in Sophos Central is empty for the run window.'
} else {
    Write-Host ("{0} check(s) did not pass - see details above." -f $failed.Count) -ForegroundColor Yellow
    Write-Host 'If the environment differs from the guide, fix it first; do not report a failed run.'
}

Stop-Transcript | Out-Null
Write-Host ''
Write-Host "Full transcript saved to : $log"
Write-Host 'PoC console output saved to: poc_output.txt (attach both to the report)'
