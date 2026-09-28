# ActiveBreach Engine vs Sophos Intercept X

Direct syscall execution on a Windows 11 host protected by Sophos Endpoint
(Intercept X): both user-mode defense layers bypassed, zero alerts in
Sophos Central.

**Author:** 0xKuraishY - September 2026
**Status:** research submitted to the Sophos bug bounty program (Bugcrowd)
on 2026-09-28. Public release follows coordinated disclosure or program
closure.

## Results

| Layer | Result |
|---|---|
| SophosED.dll user-mode hooks (4 stubs) | bypassed |
| HitmanPro.Alert SysCallX64 anti-exploit | bypassed |
| Console alerts during the complete sequence | 0 |
| Data returned through the hidden syscall | full process list (~330 KB) |
| Privileges required | standard user, no admin |

Tested on Windows 11 Pro 25H2, Intercept X 2024.1.2.10 / Core Agent
2026.2.1.3.0. Reproduced on 2026-09-17 (build 26200.9445) and re-validated
on 2026-09-28 after a Windows cumulative update (build 26200.9457, different
SophosED build, hook filter at a different offset). Same result both times.

## Quick start

On a Windows VM with Sophos Endpoint (Intercept X) installed, as a normal
user:

```
powershell -ExecutionPolicy Bypass -File .\repro.ps1
```

The script checks the environment, dumps the ntdll stubs, traces a hook into
SophosED.dll, runs the PoC, then diffs the local Sophos event logs. Every
check prints PASS/FAIL and a transcript is saved. Then open Sophos Central >
Devices > the machine > Events and confirm that no event was created for the
run. See REPRODUCTION_GUIDE.pdf for the full walkthrough (setup, build,
expected outputs, troubleshooting).

Proof (single take, desktop clock visible, ending on the empty Events page):

![PoC run](PoC.mp4)

## How ABE works (the parts that matter here)

ABE is a direct/indirect syscall execution framework:

- It maps a clean copy of ntdll.dll from disk and extracts the SSNs (system
  service numbers) by scanning the export stubs (signature
  4C 8B D1 B8 xx 00 00 00 ... 0F 05 C3).
- It builds a private syscall table (488 entries on this build), switches it
  to READONLY and logs a hash (0x17E627DBB9C53E22 here, identical on the
  clean machine and under Sophos, a nice integrity check).
- A dedicated dispatcher thread owns a ring of private syscall stubs
  (acquire, patch the SSN in, execute, release).
- With the `ntdll_backend` feature, the dispatcher prefers calling an intact
  syscall prologue inside the loaded ntdll .text instead of issuing the
  syscall from its own stub page.
- It is fail closed by design: if the export stub of a function it needs is
  detected as hooked or invalid, it refuses to start. Upstream comment
  (src/internal/vm.rs):

```rust
// If the export stub is fully hooked (no intact syscall prologue), these
// wrappers fail (return null/false). That is intentional: there is no safe
// "jump to entry"
```

- Note: in release builds, every init error is returned as 0 by AbErr()
  (upstream behavior in diagnostics.rs). Always test in debug builds and
  check the launch() return value.
- Upstream ships its own public YARA ruleset (E900U.yar in this repo) to
  detect the tool in memory: ABE is loud at rest.

## How Sophos hooks this box

Two distinct user-mode layers are in play.

Layer 1: SophosED.dll hooks. SophosED is injected into every process (48
processes on the test machine) and hooks ntdll stubs permanently,
independent of what you run. On the test box the hooked set is exactly the
memory-management and handle APIs:

| ntdll function | First bytes | State |
|---|---|---|
| NtCreateThreadEx | 4C 8B D1 B8 C9 00 00 00 | clean |
| NtQuerySystemInformation | 4C 8B D1 B8 36 00 00 00 | clean |
| NtAllocateVirtualMemory | E9 ... | hooked |
| NtProtectVirtualMemory | E9 ... | hooked |
| NtFreeVirtualMemory | E9 ... | hooked |
| NtClose | E9 ... | hooked |

A clean Win11 syscall stub starts with 4C 8B D1 B8 (mov r10, rcx ; mov eax,
SSN). A stub starting with E9 is an inline hook placed by a third party;
Microsoft never ships stubs that begin with a jmp. The hook structure,
followed jmp by jmp with a PowerShell ReadProcessMemory script:

1. Hooked stub in ntdll: the first 5 bytes of NtAllocateVirtualMemory are
   replaced by E9 <rel32>.
2. Trampoline: an anonymous private executable page, roughly 1 GB below
   ntdll (atypical allocation pattern, not a Microsoft module).
3. Gate: an indirect jmp (FF 25) whose inline pointer resolves to
   SophosED.dll base + offset (0x5F710 on the 2026-09-17 build, 0x158A90
   after the September update).
4. Filtering code inside SophosED.dll. This is the attribution step.
5. The original stub, relocated inside the trampoline page:
   4C 8B D1 B8 18 00 (SSN 0x18 = NtAllocateVirtualMemory).
6. The kernel, then a return into ntdll+5.

Important detail: Sophos only overwrites 5 bytes of the stub. The original
prologue is still there, just relocated. No Sophos alert was raised during
any of this, which is expected: the hooks are permanent instrumentation,
not a reaction. Sophos never actively detected ABE; unmodified ABE tripped
over the hooks and blocked itself.

Layer 2: HitmanPro.Alert (the anti-exploit component of Intercept X) with
its SysCallX64 mitigation. When a syscall executes such that the return
address after the syscall instruction points into an anonymous memory
region with no module attached, the process is killed. Observed correlation
(before the bypass, phase 2):

| Timestamp | Source | Detail |
|---|---|---|
| 16:27:28 | HitmanPro.Alert (ID 911) | SysCall mitigation, SysCallX64 policy, PID 11752, abe_poc.exe |
| 16:27:29 | Application Error (ID 1000) | abe_poc.exe, exception 0xC0000005, faulting module "unknown", fault offset in an anonymous region |

## Related work

The hook structure above matches the public analysis from Signal Labs
("In-Memory Disassembly for EDR/AV Unhooking", April 2023, link in
Sources). Their sample, iat_unhook_sample, solves the chicken-and-egg
problem of unhooking: most public unhooking samples call VirtualProtect or
NtProtectVirtualMemory to patch memory, but Sophos hooks
NtProtectVirtualMemory itself, so you would have to go through a hooked
function to unhook. Their approach: the original code blocks replaced by
hooks still live somewhere in memory (the EDR needs them to let legitimate
calls through); enumerate the ntdll export table, find the E9 at the start
of hooked functions, disassemble the hook in memory, follow the indirect
pointer to the relocated original block, and repoint IAT entries to it.

Their article also shows the Win11 stub layout that broke ABE's scanner
(see patch 2): after mov eax, SSN, an optional
test byte ptr [SharedUserData+0x308], 1 followed by a jne before the
syscall instruction (the KPTI switch check).

This fork is different in philosophy: it does not unhook anything. Patching
ntdll memory is visible and, per the Signal Labs article, actively blocked
by Sophos self-protection. ABE avoids hooks instead of removing them; the
patches below fix the places where that avoidance breaks down.

## The patches

All three are in `source/ActiveBreach-Engine-custom/SDK/Rust/src/internal/`,
marked with `[PATCH]` comments. The patch comments in the source are in
French (author's working language).

### Patch 1: vm.rs, Win32 fallback for the table allocation

ABE allocates its syscall table by calling the syscall prologue of the
loaded ntdll for NtAllocateVirtualMemory (then NtProtectVirtualMemory and
NtFreeVirtualMemory). With Sophos active, that prologue is hooked, so the
call ends up in SophosED's filtering code. Upstream detects the hook and
returns null; being fail closed, ABE aborts init.

The patch falls back to the plain Win32 API when the prologue call fails:

```rust
let st = f(proc, &mut base as *mut PVOID, 0,
           &mut region as *mut SizeT,
           (MEM_COMMIT | MEM_RESERVE).0, protect);

if nt_success(st) && !base.is_null() {
    return base as *mut u8;
}
// [PATCH] sinon fallback Win32 classique
fallback_alloc(size, protect)
```

The v1 of this patch (fall back only when prologue resolution returns None)
was not enough, and the reason is a trap: Sophos only overwrites 5 bytes of
the stub (4C 8B D1 B8 replaced by E9 xx xx xx xx). The upstream prologue
scanner reads 96 bytes from the export address looking for the
4C 8B D1 B8 ... 0F 05 C3 pattern. On a hooked stub, those 96 bytes run past
the 5 overwritten bytes into the next stub, which is intact. The scanner
finds the neighbor's prologue, resolves the wrong address, and the "syscall"
that executes is the one of the function next door. The call fails with a
bad NTSTATUS, and there was no fallback on that path.

The v2 fallback also triggers when the call through the prologue fails,
detected by checking the NTSTATUS and that the base pointer is not null.
The initial allocation becomes visible again (Win32 API and kernel
callbacks), which is exactly what we want to measure: does the EDR rely on
its user-mode hooks or on its kernel layer.

### Patch 2: exports.rs, tolerant prologue scanner

Modern Win11 stubs can carry an optional block between mov eax, SSN and the
syscall instruction:

```
4C 8B D1 B8 xx 00 00 00          mov r10, rcx ; mov eax, SSN
F6 04 25 08 03 FE 7F 01          test byte ptr [SharedUserData+0x308], 1
75 xx / 0F 85 xx xx xx xx        jne ...
0F 05 C3                           syscall ; ret
```

That test is the KPTI switch check. The upstream prologue validator expects
0F 05 right after the mov eax and rejects the stub otherwise. On this 25H2
build the block is present, so every validation failed, the prologue cache
stayed empty, and the dispatcher was forced onto the private stub every
time (which then dies on layer 2). The patch makes the scanner skip the
optional F6 04 25 ... 01 block and the conditional jump that follows:

```rust
if i + 9 <= pro.len() && pro[i] == 0xF6 && pro[i + 1] == 0x04
    && pro[i + 2] == 0x25 && pro[i + 7] == 0x01 {
    i += 8;
}
if i + 2 <= pro.len() && pro[i] == 0x75 {
    i += 2;
} else if i + 6 <= pro.len() && pro[i] == 0x0F && pro[i + 1] == 0x85 {
    i += 6;
}
```

### Patch 3: dispatch.rs [L3], direct prologue call

Even in ntdll_backend mode, the upstream dispatcher does not call the cached
prologue directly. It writes a jump stub (write_jmp64_stub) into its own
private RX page and calls that. At the syscall instruction, the return
address points into anonymous private memory: exactly the SysCallX64
signature, and the process is killed with 0xC0000005.

Spoofing the return address alone was tried first: the process still got
killed. The mitigation does not only look at the stack value; it also sees
where the syscall instruction physically executes.

The patch calls the cached prologue pointer directly from the dispatcher:

```rust
if let Some(target) = direct_call {
    let direct_fn: ABStubFn = unsafe { std::mem::transmute(target) };
    direct_fn(regs[0], regs[1], ...);
}
```

The syscall then executes inside the ntdll .text, and the kernel returns
into the .text of activebreach.dll, a real module. Both conditions of the
heuristic are invalidated: execution in a real module, return into a real
module. The cached pointer is re-validated before each call (still inside
the ntdll .text range) so a hook added at runtime is not silently used.

## How the bypass was found (summary)

1. **Why does it hang**: first run (release build) printed
   "activebreach_launch() returned: 0" then blocked forever, CPU at 0%.
   System Informer showed the main thread waiting in ntdll!WaitOnAddress
   inside ab_call, no dispatcher thread, three SophosED threads injected.
   A debug build revealed the real state: launch() returned -1076909169
   (0xBFCFAB8F); the engine was failing init right after opening ntdll,
   silently, and the release build masked the error as 0.
2. **Attribution**: stub dump (table above), trampoline chain followed to
   SophosED.dll+0x5F710, then an A/B test: uninstall Sophos, reboot, same
   DLL, same PoC. Full init sequence appeared and the syscall returned
   256 KB of process list. Causality confirmed.
3. **Past the hooks, into the anti-exploit**: patch 1 (v2) got init through
   under active hooks (table hash identical to the clean machine). The
   process then died at the moment of syscall execution, exit 0xC0000005,
   HitmanPro.Alert ID 911 correlated one second apart.
4. **The direct call**: return-address spoofing first (still killed), then
   patch 3. Result on 2026-09-17, Sophos active, four of six checked stubs
   hooked: full init under hooks, NtQuerySystemInformation executed,
   288280 bytes returned, zero alerts in Sophos Central. The only remaining
   observer is the kernel layer (Ob/Ps callbacks, ETW Threat Intelligence),
   which sees the allocations and the thread creation but did not correlate
   anything into an alert.

Full narrative with logs: Report_ABE_Sophos_0xKuraishY_EN.pdf.

## Test environment

| Item | Detail |
|---|---|
| Dates | 2026-09-16/17 (bypass), 2026-09-21 (video), 2026-09-28 (re-validation + AAP retest) |
| OS | Windows 11 Pro 25H2, builds 26200.9445 and 26200.9457 (x64, isolated Proxmox VM, snapshot before tests) |
| Toolchain | Rust 1.82 (x86_64-pc-windows-msvc), VS Build Tools 2022 |
| EDR under test | Sophos Endpoint: SophosED.dll + HitmanPro.Alert (Intercept X 2024.1.2.10, Core Agent 2026.2.1.3.0) |
| Table hash | 0x17E627DBB9C53E22 (identical on clean machine and under Sophos), 488 SSNs |

## Adaptive Attack Protection (AAP) note

AAP was OFF during the main test: it cannot be left enabled permanently
(72 hours maximum per machine) and enabling it disrupts normal usage
(internet access cut, legitimate applications such as PowerShell flagged as
"controlled"). The default steady state is what this repo measures.

Retest with AAP manually enabled (2026-09-28, inside its 72-hour window):
the PoC was detected, but the alert is classified Disrupt_2a / MITRE
T1574.002 (DLL side-loading) - the engine reacted to the loader shape
(unsigned exe loading a DLL from its own directory), not to the
direct-syscall activity, which produced no event in either state. After this
detection, the on-access scanner later removed abe_poc.exe from disk. The
standing configuration is bypassed silently; the temporary containment mode
catches this specific packaging only. Note that Sophos Central also logged
"Adaptive Attack Protection turned on by administrator" - an audit event,
not a detection.

## Detection notes

The result is not "Sophos is broken". It is "user-mode heuristics are not a
sufficient control". Recommendations, confirmed by the bypass:

- Stack-walking in kernel callbacks: memory allocation and thread creation
  callbacks should check the return address. A return into a private RX
  region with no module attached is the direct-syscall signature; a direct
  ntdll prologue call from a third-party module (bypassing
  kernelbase/kernel32) is also abnormal. Invisible from user mode, visible
  only from the kernel.
- Memory scanning for syscall stubs: the signature
  4C 8B D1 B8 xx 00 00 00 0F 05 C3 outside ntdll is a home-made stub. ABE
  creates dozens of them in its pool. Simple detection, almost no false
  positives (upstream ships exactly this in E900U.yar).
- Hook self-integrity: the EDR knows the byte it wrote (E9) at the start of
  its hooked stubs. Any restoration or replacement must raise an alert.
- Correlate existing kernel telemetry (ETW-TI, Ob/Ps callbacks) into
  visible alerts. The striking fact of this test: none of that telemetry
  became an alert on the console during the whole sequence.
- HVCI / VBS and kernel-mode code integrity make private stub creation and
  execution significantly more expensive for the attacker.

## Build

Prerequisites: Rust 1.82+ with the x86_64-pc-windows-msvc target and
Visual Studio Build Tools 2022. Internet access for the first build (cargo
downloads dependencies).

```
:: 1. engine DLL (debug build: real error codes and logs)
cd source\ActiveBreach-Engine-custom\SDK\Rust
cargo build --features ntdll_backend

:: 2. PoC executable
cd ..\..\poc
cargo build

:: 3. place both binaries at the package root (they must sit together)
copy ..\..\..\SDK\Rust\target\debug\activebreach.dll ..\..\..
copy target\debug\abe_poc.exe ..\..\..
```

Expected on successful init: SYSCALL_TABLE initialized (entries=488),
READONLY, hash 0x17E627DBB9C53E22, dispatcher thread, stub pool. Under
active Sophos with the patches: "[L3]" line, "SUCCESS! Syscall executed
without detection", ReturnLength in the hundreds of KB. The process then
exits with 0xC0000005 after printing the result (post-execution reaction,
documented in the report section E.3; the syscall completed before it).

## Repo layout

| Path | Description |
|---|---|
| `repro.ps1` | automated reproduction: environment check, stub dump, SophosED attribution, event-log diff, PoC run with PASS/FAIL checks |
| `REPRODUCTION_GUIDE.pdf` | step-by-step guide (setup, run, verification, troubleshooting) |
| `Report_ABE_Sophos_0xKuraishY_EN.pdf` | full technical report (15 pages) |
| `activebreach.dll` / `abe_poc.exe` | patched engine + PoC, debug builds |
| `SHA256SUMS.txt` | SHA256 of the two binaries |
| `repro_output_20260928_115207.txt`, `poc_output.txt` | validation run transcripts |
| `PoC.cleaned.mp4` | screen recording of a complete run (single take) |
| `source/ActiveBreach-Engine-custom/` | full patched source (engine in SDK/Rust, PoC in poc/) |

## Known limits

- This work targets the user-mode layer only (SophosED hooks, SysCallX64).
  Kernel callbacks (Ob/Ps) and ETW Threat Intelligence still observe memory
  allocations and thread creation; nothing was correlated into an alert
  during the tests, but the telemetry exists.
- If no clean prologue is cached for a given syscall, the dispatcher falls
  back to the private stub and can still be killed by SysCallX64.
- Patch 1 makes the initial allocation go through the Win32 API, so that
  allocation is visible to anyone watching kernel callbacks. Deliberate
  tradeoff to measure the EDR's reliance on user-mode hooks.
- Post-execution behavior not fully qualified: the process exits with
  0xC0000005 after printing the result (no event in the console).
- Rust SDK only; the upstream C and C++ SDKs are not patched.

## Credits

- Original ABE: 8damon/ActiveBreach-Engine (copyright 2026 RYFTENIUS,
  Apache 2.0 with Commons Clause).
- Hook analysis and relocated-stub technique: Signal Labs, "In-Memory
  Disassembly for EDR/AV Unhooking", April 2023 (link below).
- Patches, PoC, evaluation: 0xKuraishY, September 2026.

## Sources

- Jackson_T, "SysWhispers", 2019 - https://github.com/jthuraisamy/SysWhispers
- am0nsec and smelly__vx, "Hell's Gate", 2020 - https://github.com/am0nsec/HellsGate
- Reenz0h (Sektor7), "Halo's Gate", 2021 - https://blog.sektor7.net/#!res/2021/halosgate.md
- Paul Laine (trickster0), "Tartarus' Gate", 2021 - https://github.com/trickster0/TartarusGate
- Outflank, "Combining Direct System Calls and sRDI to bypass AV/EDR", 2019 - https://www.outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
- Signal Labs, "In-Memory Disassembly for EDR/AV Unhooking", April 2023 - https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/ (sample: https://github.com/Signal-Labs/iat_unhook_sample)
- Palantir, "Tampering with Windows Event Tracing: Background, Offense, and Defense", December 2018 - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
- "Lifting the veil, a look at MDE under the hood" (ETW Threat Intelligence as EDR telemetry), Troopers 2022 - https://troopers.de/downloads/troopers22/TR22_LiftingTheVeilALookAtMDE.pdf
- Virus Bulletin 2025, "Evading in plain sight: how adversaries beat user-mode protection engines for over a decade" - https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Evading-in-plain-sight-how-adversaries-beat-user-mode-protection-engines-for-over-a-decade.pdf

## Disclaimer

Research on an isolated lab machine against a product installed from an
official free trial. The PoC demonstrates a detection gap and suggests
mitigations; it is not a weaponized tool. Do not deploy outside an
authorized scope.
