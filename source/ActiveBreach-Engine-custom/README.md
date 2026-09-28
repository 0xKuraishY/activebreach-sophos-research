EN //

# ActiveBreach-Engine (custom fork)

Fork of [ActiveBreach-Engine v0.2.0](https://github.com/8damon/ActiveBreach-Engine)
with patches to make it run under an active EDR. Tested and validated against
Sophos Endpoint (SophosED + HitmanPro.Alert, Intercept X) on Windows 11.

Lab work, internal use and defensive research only.

## What this fork is

The original tool does not work out of the box on a machine protected by
Sophos Endpoint. This repo contains the modified Rust SDK plus a small POC
that loads the resulting DLL and issues a direct syscall while the agent is
running. Three patches were needed to get from "infinite hang" to "syscall
executed, no alert in Sophos Central".

Everything below was observed on a real box: Windows 11 Pro 25H2 build
26200.9445, Sophos Endpoint Intercept X 2024.1.2.10 (Core Agent
2026.2.1.3.0). Dates of the tests: 16 and 17 September 2026.

## How ABE works (the parts that matter here)

ABE is a direct/indirect syscall execution framework. In a nutshell:

- It maps a clean copy of ntdll.dll from disk and extracts the SSNs
  (system service numbers) by scanning the export stubs
  (signature 4C 8B D1 B8 xx 00 00 00 ... 0F 05 C3).
- It builds a private syscall table (488 entries on this build), switches it
  to READONLY and logs a hash of it (0x17E627DBB9C53E22 here, identical on
  the clean machine and under Sophos, which is a nice integrity check).
- A dedicated dispatcher thread owns a ring of private syscall stubs
  (acquire, patch the SSN in, execute, release).
- With the `ntdll_backend` feature, the dispatcher prefers calling an intact
  syscall prologue inside the loaded ntdll .text instead of issuing the
  syscall from its own stub page.
- It is fail closed by design: if the export stub of a function it needs is
  detected as hooked or invalid, it refuses to start. Comment straight from
  the upstream source (src/internal/vm.rs):

```rust
// If the export stub is fully hooked (no intact syscall prologue), these
// wrappers fail (return null/false). That is intentional: there is no safe
// "jump to entry"
```

- Upstream ships its own public YARA ruleset (E900U.yar in this repo) to
  detect the tool in memory. Keep that in mind: ABE is loud at rest.

## How Sophos hooks this box

Two distinct user mode layers are in play.

Layer 1: SophosED.dll hooks. SophosED is injected into every process and
hooks ntdll stubs permanently, independent of what you run. On this box the
hooked set is exactly the memory management APIs:

| ntdll function | First bytes | State |
|----------------|-------------|-------|
| NtCreateThreadEx | 4C 8B D1 B8 C9 00 00 00 | clean |
| NtQuerySystemInformation | 4C 8B D1 B8 36 00 00 00 | clean |
| NtAllocateVirtualMemory | E9 A3 F2 FE BF ... | hooked |
| NtProtectVirtualMemory | E9 ... | hooked |
| NtFreeVirtualMemory | E9 ... | hooked |
| NtClose | E9 ... | hooked |

A clean Win11 syscall stub starts with 4C 8B D1 B8. A stub starting with E9
is an inline hook placed by a third party; Microsoft never ships stubs that
begin with a jmp. The hook structure, followed jmp by jmp with a small
PowerShell script (ReadProcessMemory):

1. Hooked stub in ntdll: the first 5 bytes of NtAllocateVirtualMemory are
   replaced by E9 <rel32>.
2. Trampoline: an anonymous private executable page, roughly 1 GB below
   ntdll (typical allocation pattern, not a Microsoft module).
3. Gate: an indirect jmp (FF 25) whose inline pointer is 0x7FFE4CA2F710.
4. Filtering code: 0x7FFE4CA2F710 = SophosED.dll base + 0x5F710. This is the
   attribution step.
5. The original stub, relocated inside the trampoline page:
   4C 8B D1 B8 18 00 (SSN 0x18 = NtAllocateVirtualMemory).
6. The kernel, then a return into ntdll+5.

Important detail for later: Sophos only overwrites 5 bytes of the stub.
The original prologue is still there, just relocated.

No Sophos alert was raised during any of this, which is expected. The hooks
are permanent instrumentation. Sophos never actively detected ABE; ABE
tripped over the hooks and blocked itself.

Layer 2: HitmanPro.Alert (the anti exploit component of Intercept X) with
its SysCallX64 mitigation. When a syscall executes such that the return
address (RIP after the syscall instruction) points into an anonymous memory
region with no module attached, the process is killed. Observed correlation:

| Timestamp | Source | Detail |
|-----------|--------|--------|
| 16:27:28 | HitmanPro.Alert (ID 911) | SysCall mitigation, SysCallX64 policy, PID 11752, abe_poc.exe |
| 16:27:29 | Application Error (ID 1000) | abe_poc.exe, exception 0xC0000005, faulting module "unknown", fault offset in an anonymous region |

## Related work

The hook structure above matches the public analysis from Signal Labs
("In-Memory Disassembly for EDR/AV Unhooking", April 2023). Their sample,
[iat_unhook_sample](https://github.com/Signal-Labs/iat_unhook_sample),
solves a problem this test also runs into: the chicken and egg problem of
unhooking. Most public unhooking samples call VirtualProtect or
NtProtectVirtualMemory to patch memory, but Sophos hooks
NtProtectVirtualMemory itself, so you would have to go through a hooked
function to unhook, and Sophos blocks exactly that.

Their approach: the original code blocks replaced by hooks still live
somewhere in memory (the EDR needs them to let legitimate calls through).
They enumerate the ntdll export table, find the E9 at the start of hooked
functions, disassemble the hook in memory, follow the indirect pointer to
the relocated original block, and repoint the IAT entries to it. No direct
syscall, no call to a hooked API.

The screenshots in their article also show the Win11 stub layout that broke
ABE's scanner (see patch 2): after mov eax, SSN, an optional
test byte ptr [SharedUserData+0x308], 1 followed by a jne before the
syscall instruction.

What this fork does is different in philosophy: it does not unhook anything.
Patching ntdll memory is visible and, per the Signal Labs article, actively
blocked by Sophos self protection. ABE's own philosophy is to avoid hooks,
not remove them. The patches below fix the places where that avoidance
breaks down.

## The patches

### Patch 1: vm.rs, Win32 fallback for the table allocation

ABE allocates its syscall table by calling the syscall prologue of the
loaded ntdll for NtAllocateVirtualMemory (and later NtProtectVirtualMemory
and NtFreeVirtualMemory). With Sophos active, that prologue is hooked, so
the call ends up in SophosED's filtering code. The upstream code detects
the hook and returns null; being fail closed, ABE aborts init.

The patch adds a fallback to the plain Win32 API when the prologue call
fails:

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

The v1 of this patch (fall back only when the prologue resolution returns
None) was not enough, and the reason is a trap: Sophos only overwrites
5 bytes of the stub (4C 8B D1 B8 replaced by E9 xx xx xx xx). The upstream
prologue scanner reads 96 bytes from the export address looking for the
4C 8B D1 B8 ... 0F 05 C3 pattern. On a hooked stub, those 96 bytes run past
the 5 overwritten bytes and into the next stub, which is intact. The
scanner finds the neighbor's prologue, resolves the wrong address, and the
"syscall" that executes is the one of the function next door. The call then
fails with a bad NTSTATUS, but there was no fallback on that path.

The v2 fallback also triggers when the call through the prologue fails,
detected by checking the NTSTATUS and that the base pointer is not null.
The initial allocation becomes visible again (Win32 API and kernel
callbacks), which is exactly what we want to measure: does Sophos rely on
its user mode hooks or on its kernel layer.

### Patch 2: exports.rs, tolerant prologue scanner

Modern Win11 stubs can carry an optional block between mov eax, SSN and
the syscall instruction:

```
4C 8B D1 B8 xx 00 00 00          mov r10, rcx ; mov eax, SSN
F6 04 25 08 03 FE 7F 01          test byte ptr [SharedUserData+0x308], 1
75 xx / 0F 85 xx xx xx xx        jne ...
0F 05 C3                           syscall ; ret
```

That test is the KPTI switch check. The upstream prologue validator expects
0F 05 right after the mov eax and rejects the stub otherwise. On this
25H2 build the block is present, so every validation failed and the
prologue cache stayed empty, forcing the dispatcher onto the private stub
every time (which then dies on layer 2). The patch makes the scanner skip
the optional F6 04 25 ... 01 block and the conditional jump that follows:

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
address points into anonymous private memory. That is exactly the signature
of the SysCallX64 policy, and the process gets killed with 0xC0000005.

Spoofing the return address alone was tried first: the process still got
killed. The mitigation does not only look at the stack value, it also sees
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
module. The cached pointer is re validated before each call (still inside
the ntdll .text range) so a hook added at runtime is not silently used.

## How the bypass was found

### Phase 1: why does it hang

First run of the POC (release build): the process prints
"activebreach_launch() retourne : 0" and then blocks forever on the syscall
call, no message, CPU at 0%. The upstream guide claims that launch()
returning 0 means success. It does not: in release builds, AbErr() returns
0 for every error kind (upstream behavior in diagnostics.rs), so the init
failure was indistinguishable from a success and the POC went on to call
ab_call with no dispatcher running.

System Informer on the stuck process:

- one active thread (the main thread), waiting in ntdll!WaitOnAddress,
  called from activebreach.dll!ab_call
- no dispatcher thread inside activebreach.dll, although the mechanism
  requires one
- three SophosED.dll threads injected into the process

The main thread was correctly waiting for an answer from a dispatcher that
never started. The hang is a symptom, not the cause.

A debug build revealed the real state immediately: launch() returned
-1076909169 (0xBFCFAB8F) and the last log line was the mapper opening
C:\Windows\System32\ntdll.dll. The engine was failing during init, right
after opening ntdll, silently. Without the debug build this error would
have stayed invisible.

From there: stub dump with ReadProcessMemory (table above), trampoline
chain followed jmp by jmp down to SophosED.dll+0x5F710, then an A/B test.
Uninstalled Sophos, rebooted, same DLL, same POC. The full init sequence
appeared (488 SSNs, READONLY, hash 0x17E627DBB9C53E22, dispatcher thread,
stub pool) and the syscall returned 256 KB of process list. Causality
confirmed.

### Phase 2: past the hooks, into the anti exploit

Patch 1 (v2) got the init through under active hooks, table hash identical
to the clean machine. Then the process died silently at the moment of the
syscall execution, exit code 0xC0000005. Event Viewer correlated
HitmanPro.Alert ID 911 (SysCall mitigation, SysCallX64 policy) with the
application error one second apart. Same PID.

Analysis of the mechanism (details in the layer 2 section above): the
private jump stub is what kills it.

### Phase 3: the direct call

Return address spoofing first, still killed. Then patch 3: direct call of
the cached ntdll prologue from the dispatcher, plus patch 2 so the prologue
cache actually fills on this Win11 build.

Result on 17/09/2026, Sophos active, four out of six checked stubs hooked:

- full init under active hooks (table hash 0x17E627DBB9C53E22, identical to
  the clean machine)
- NtQuerySystemInformation executed, 288280 bytes of process list returned
- zero alerts in Sophos Central during the whole sequence
- the only remaining observer is the kernel layer (Ob/Ps callbacks, ETW
  Threat Intelligence), which sees the allocations and the thread creation
  but did not correlate anything into an alert during the test

## Test environment and results

| Item | Detail |
|------|--------|
| Dates | 16 and 17 September 2026 |
| OS | Windows 11 Pro 25H2, build 26200.9445 (x64, isolated Proxmox VM, snapshot before tests) |
| Toolchain | Rust 1.82 (x86_64-pc-windows-msvc), VS Build Tools 2022 |
| EDR under test | Sophos Endpoint: SophosED.dll + HitmanPro.Alert (Intercept X 2024.1.2.10, Core Agent 2026.2.1.3.0) |
| SophosED user mode hooks | bypassed (full init under active hooks) |
| SysCallX64 mitigation | bypassed (direct prologue call) |
| Sophos Central alerts | none during init, syscall execution or process exit |
| Kernel telemetry | last observer standing, not correlated into alerts |
| Table hash | 0x17E627DBB9C53E22 (identical to the clean machine), 488 SSNs |
| POC result | NtQuerySystemInformation, ReturnLength 288280 bytes |

Execution proof of 17/09/2026 (Sophos Central console with no alert on the
left, full POC output on the right) is in the full report:
Rapport_Evaluation_ABE_Sophos_v2-1.pdf.

## Detection notes

The test result is not "Sophos is broken". It is "user mode heuristics are
not a sufficient control". Concrete recommendations, confirmed by the
bypass:

- Stack walking in kernel callbacks: memory allocation and thread creation
  callbacks should check the return address. A return into a private RX
  region with no module attached is the direct syscall signature; a direct
  ntdll prologue call from a third party module (bypassing
  kernelbase/kernel32) is also abnormal. Invisible from user mode, visible
  only from the kernel.
- Memory scan for syscall stubs: the signature
  4C 8B D1 B8 xx 00 00 00 0F 05 C3 outside ntdll is a home made stub. ABE
  creates dozens of them in its pool. Simple detection, almost no false
  positives. Upstream ships exactly this in E900U.yar.
- Hook self integrity: the EDR knows the byte it wrote (E9) at the start of
  its hooked stubs. Any restoration or replacement must raise an alert
  immediately.
- Correlate existing kernel telemetry (ETW TI, Ob/Ps callbacks) into
  visible alerts. The striking fact of this test: none of that telemetry
  became an alert on the console during the whole sequence.
- HVCI / VBS and kernel mode code integrity make private stub creation and
  execution significantly more expensive for the attacker.

## Build

### DLL (SDK/Rust)

```powershell
cd SDK\Rust

# debug (recommended for testing: real error codes are logged)
cargo build --features ntdll_backend

# release
cargo build --release --features ntdll_backend
```

Note: in release builds every init error is returned as 0 by AbErr()
(upstream behavior, not modified here). Always check the return value of
activebreach_launch() and test in debug first.

Expected output on successful init:

```
[AB:MAPPER]  Opening C:\Windows\System32\ntdll.dll
[AB:EXPORTS] SYSCALL_TABLE initialized @0x... (entries=488)
[AB:EXPORTS] SYSCALL_TABLE set to READONLY
[AB:EXPORTS] SYSCALL_TABLE hash = 0x17E627DBB9C53E22
[AB:DISPATCH] dispatcher thread started
[AB:STUB] stub pool ready
```

### POC (poc/ folder)

Loads activebreach.dll with libloading, checks the launch() return value,
then issues NtQuerySystemInformation (class 5, SystemProcessInformation)
through ab_call with a 1 MB buffer. The syscall is issued by name; the
dispatcher resolves the SSN and the prologue from the syscall table.

```powershell
cd poc
cargo build --release
# put activebreach.dll next to the executable
# (a prebuilt DLL is included in the repo, ~288 KB)
```

Expected output under active Sophos:

```
[*] Lancement d'ActiveBreach...
[+] activebreach_launch() retourne : 0
[*] Appel NtQuerySystemInformation via ABE...
[AB:DISPATCH][L3] appel direct du prologue ntdll
[+] SUCCES ! Syscall execute sans detection.
ReturnLength = 288280 octets
[*] POC termine.
```

## Repo layout

- `SDK/Rust/` : modified Rust SDK (the three patches are in
  `src/internal/vm.rs`, `src/internal/exports.rs`,
  `src/internal/dispatch.rs`, grep for `[PATCH`)
- `poc/` : POC loader (Rust, libloading), includes a prebuilt
  activebreach.dll
- `E900U.yar` : upstream public YARA ruleset for detecting ABE in memory
- `Diagram/` : upstream architecture diagrams
- `Rapport_Evaluation_ABE_Sophos_v2-1.pdf` : full evaluation report
  (diagnosis, attribution, A/B test, the three bypass phases, detection
  recommendations)

## Known limits

- This fork only targets the user mode layer (SophosED hooks and SysCallX64).
  Kernel callbacks (Ob/Ps) and ETW Threat Intelligence still observe memory
  allocations and thread creation. Nothing was correlated into an alert on
  the console during the test, but the telemetry exists.
- If no clean prologue is cached for a given syscall, the dispatcher falls
  back to the private stub and can still get killed by SysCallX64.
- Patch 1 makes the initial allocation go through the Win32 API, so that
  allocation is visible to anyone watching kernel callbacks. That is a
  deliberate tradeoff to measure the EDR's reliance on user mode hooks.
- Post execution behavior not fully qualified: the process exits with
  0xC0000005 after printing "POC termine." (no event in the Sophos console,
  result not affected).
- The C and C++ SDKs are not patched (Rust only).

## Credits

- Original ABE: [8damon/ActiveBreach-Engine](https://github.com/8damon/ActiveBreach-Engine),
  copyright 2026 RYFTENIUS, Apache 2.0 license with Commons Clause
  (no commercial use).
- Hook analysis and relocated stub technique: Signal Labs,
  "In-Memory Disassembly for EDR/AV Unhooking", April 2023.
  https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/
  Sample code: https://github.com/Signal-Labs/iat_unhook_sample
- Patches, POC and evaluation report: 0xKuraishY, September 2026.

## Disclaimer

This tool is meant for offensive security research and for evaluating EDR
resilience, in an isolated lab environment and with explicit authorization.
Do not deploy it on systems outside an authorized scope.








FR //

# ActiveBreach-Engine (fork custom)

Fork d'[ActiveBreach-Engine v0.2.0](https://github.com/8damon/ActiveBreach-Engine)
avec des patches pour le faire tourner sous EDR actif. Teste et valide contre
Sophos Endpoint (SophosED + HitmanPro.Alert, Intercept X) sur Windows 11.

Travail de laboratoire, usage interne et recherche defensive uniquement.
Version anglaise : README.md.

## Ce qu'est ce fork

L'outil original ne fonctionne pas tel quel sur une machine protegee par
Sophos Endpoint. Ce repo contient le SDK Rust modifie plus un petit POC qui
charge la DLL resultante et execute un syscall direct pendant que l'agent
tourne. Trois patches ont ete necessaires pour passer du "blocage infini"
au "syscall execute, aucune alerte dans Sophos Central".

Tout ce qui suit a ete observe sur une vraie machine : Windows 11 Pro 25H2
build 26200.9445, Sophos Endpoint Intercept X 2024.1.2.10 (Core Agent
2026.2.1.3.0). Dates des tests : 16 et 17 septembre 2026.

## Comment ABE fonctionne (les parties qui comptent ici)

ABE est un framework d'execution de syscalls directs/indirects. En resume :

- Il mappe une copie propre de ntdll.dll depuis le disque et extrait les
  SSN (system service numbers) en scannant les stubs d'export
  (signature 4C 8B D1 B8 xx 00 00 00 ... 0F 05 C3).
- Il construit une table de syscalls privee (488 entrees sur ce build),
  la passe en READONLY et log un hash de controle (0x17E627DBB9C53E22 ici,
  identique sur la machine propre et sous Sophos, ce qui est un bon
  controle d'integrite).
- Un thread dispatcher dedie possede un anneau de stubs syscall prives
  (acquire, patch du SSN, execution, release).
- Avec le feature `ntdll_backend`, le dispatcher prefere appeler un
  prologue syscall intact dans le .text du ntdll charge au lieu d'emettre
  le syscall depuis sa propre page de stubs.
- Il est fail closed par construction : si le stub d'export d'une fonction
  dont il a besoin est detecte comme hooke ou invalide, il refuse de
  demarrer. Commentaire tire du source upstream (src/internal/vm.rs) :

```rust
// If the export stub is fully hooked (no intact syscall prologue), these
// wrappers fail (return null/false). That is intentional: there is no safe
// "jump to entry"
```

- L'auteur upstream fournit son propre ruleset YARA public (E900U.yar dans
  ce repo) pour detecter l'outil en memoire. Gardez ca en tete : ABE est
  bruyant au repos.

## Comment Sophos hook cette machine

Deux couches distinctes en mode utilisateur entrent en jeu.

Couche 1 : les hooks SophosED.dll. SophosED est injecte dans chaque
processus et hook les stubs ntdll en permanence, independamment de ce que
vous lancez. Sur cette machine, l'ensemble hooke correspond exactement aux
API de gestion memoire :

| fonction ntdll | premiers octets | etat |
|----------------|-----------------|------|
| NtCreateThreadEx | 4C 8B D1 B8 C9 00 00 00 | sain |
| NtQuerySystemInformation | 4C 8B D1 B8 36 00 00 00 | sain |
| NtAllocateVirtualMemory | E9 A3 F2 FE BF ... | hooke |
| NtProtectVirtualMemory | E9 ... | hooke |
| NtFreeVirtualMemory | E9 ... | hooke |
| NtClose | E9 ... | hooke |

Un stub syscall sain de Win11 commence par 4C 8B D1 B8. Un stub commencant
par E9 est un hook inline pose par un tiers ; Microsoft ne livre jamais de
stubs qui commencent par un jmp. Structure du hook, suivie jmp par jmp avec
un petit script PowerShell (ReadProcessMemory) :

1. Stub hooke dans ntdll : les 5 premiers octets de NtAllocateVirtualMemory
   sont remplaces par E9 <rel32>.
2. Trampoline : une page anonyme privee executable, a environ 1 Go sous
   ntdll (pattern d'allocation type, pas un module Microsoft).
3. Gate : un jmp indirect (FF 25) dont le pointeur inline vaut
   0x7FFE4CA2F710.
4. Code de filtrage : 0x7FFE4CA2F710 = base de SophosED.dll + 0x5F710.
   C'est l'etape d'attribution.
5. Le stub original, relocalise dans la page trampoline :
   4C 8B D1 B8 18 00 (SSN 0x18 = NtAllocateVirtualMemory).
6. Le noyau, puis un retour dans ntdll+5.

Detail important pour la suite : Sophos n'ecrase que 5 octets du stub. Le
prologue original est toujours la, juste deplace.

Aucune alerte Sophos n'a ete levee pendant tout cela, ce qui est attendu.
Les hooks sont de l'instrumentation permanente. Sophos n'a jamais
activement detecte ABE ; ABE a trebuche sur les hooks et s'est bloque
lui-meme.

Couche 2 : HitmanPro.Alert (le composant anti exploit d'Intercept X) avec
sa mitigation SysCallX64. Quand un syscall s'execute de telle sorte que
l'adresse de retour (RIP apres l'instruction syscall) pointe dans une
region anonyme sans module associe, le processus est tue. Correlation
observee :

| horodatage | source | detail |
|------------|--------|--------|
| 16:27:28 | HitmanPro.Alert (ID 911) | mitigation SysCall, politique SysCallX64, PID 11752, abe_poc.exe |
| 16:27:29 | Application Error (ID 1000) | abe_poc.exe, exception 0xC0000005, module defaillant "unknown", fault offset dans une region anonyme |

## Travaux lies

La structure du hook ci-dessus correspond a l'analyse publique de Signal
Labs ("In-Memory Disassembly for EDR/AV Unhooking", avril 2023). Leur
exemple, [iat_unhook_sample](https://github.com/Signal-Labs/iat_unhook_sample),
resout un probleme que ce test rencontre aussi : le probleme de la poule
et de l'oeuf du unhooking. La plupart des samples publics d'unhooking
appellent VirtualProtect ou NtProtectVirtualMemory pour patcher la
memoire, mais Sophos hook NtProtectVirtualMemory elle-meme, donc il
faudrait passer par une fonction hookee pour unhooker, et Sophos bloque
exactement ca.

Leur approche : les blocs de code originaux remplaces par les hooks vivent
encore quelque part en memoire (l'EDR en a besoin pour laisser passer les
appels legitimes). Ils enumerent la table d'export de ntdll, trouvent le
E9 au debut des fonctions hookees, desassemblent le hook en memoire,
suivent le pointeur indirect jusqu'au bloc original relocalise, et
repointent les entrees IAT dessus. Pas de syscall direct, pas d'appel a une
API hookee.

Les captures d'article de Signal Labs montrent aussi le layout de stub
Win11 qui a casse le scanner d'ABE (voir patch 2) : apres mov eax, SSN, un
bloc optionnel test byte ptr [SharedUserData+0x308], 1 suivi d'un jne
avant l'instruction syscall.

Ce que fait ce fork est different dans la philosophie : il ne desinstalle
aucun hook. Patcher la memoire de ntdll est visible et, selon l'article de
Signal Labs, activement bloque par la self protection de Sophos. La
philosophie d'ABE est d'eviter les hooks, pas de les supprimer. Les
patches ci-dessous reparent les endroits ou cet evitement se brise.

## Les patches

### Patch 1 : vm.rs, fallback Win32 pour l'allocation de la table

ABE alloue sa table de syscalls en appelant le prologue syscall du ntdll
charge pour NtAllocateVirtualMemory (puis NtProtectVirtualMemory et
NtFreeVirtualMemory). Avec Sophos actif, ce prologue est hooke, donc
l'appel finit dans le code de filtrage de SophosED. Le code upstream
detecte le hook et retourne null ; etant fail closed, ABE abandonne l'init.

Le patch ajoute un fallback sur l'API Win32 classique quand l'appel via le
prologue echoue :

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

La v1 de ce patch (fallback uniquement quand la resolution du prologue
retourne None) n'etait pas suffisante, et la raison est un piege : Sophos
n'ecrase que 5 octets du stub (4C 8B D1 B8 remplaces par E9 xx xx xx xx).
Le scanner de prologues upstream lit 96 octets depuis l'adresse d'export a
la recherche du pattern 4C 8B D1 B8 ... 0F 05 C3. Sur un stub hooke, ces
96 octets depassent les 5 octets ecrases et arrivent dans le stub voisin,
qui est intact. Le scanner trouve le prologue du voisin, resout la mauvaise
adresse, et le "syscall" qui s'execute est celui de la fonction d'a cote.
L'appel echoue alors avec un NTSTATUS incorrect, mais il n'y avait pas de
fallback sur ce chemin.

La v2 declenche le fallback aussi quand l'appel via le prologue echoue,
detecte par le controle du NTSTATUS et du pointeur de base non nul.
L'allocation initiale redevient visible (API Win32 et callbacks noyau), ce
qui est exactement ce qu'on veut mesurer : Sophos repose-t-il sur ses
hooks mode utilisateur ou sur sa couche noyau.

### Patch 2 : exports.rs, scanner de prologues tolerant

Les stubs Win11 modernes peuvent comporter un bloc optionnel entre
mov eax, SSN et l'instruction syscall :

```
4C 8B D1 B8 xx 00 00 00          mov r10, rcx ; mov eax, SSN
F6 04 25 08 03 FE 7F 01          test byte ptr [SharedUserData+0x308], 1
75 xx / 0F 85 xx xx xx xx        jne ...
0F 05 C3                           syscall ; ret
```

Ce test est le check de commutation KPTI. Le validateur de prologue
upstream attend 0F 05 juste apres le mov eax et rejette le stub sinon. Sur
ce build 25H2 le bloc est present, donc chaque validation echouait et le
cache de prologues restait vide, forcant le dispatcher sur le stub prive a
chaque fois (qui se fait ensuite tuer par la couche 2). Le patch rend le
scanner tolerant : il saute le bloc optionnel F6 04 25 ... 01 et le saut
conditionnel qui suit :

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

### Patch 3 : dispatch.rs [L3], appel direct du prologue

Meme en mode ntdll_backend, le dispatcher upstream n'appelle pas le
prologue en cache directement. Il ecrit un stub de saut
(write_jmp64_stub) dans sa propre page RX privee et appelle ca. Au moment
de l'instruction syscall, l'adresse de retour pointe dans une memoire
privee anonyme. C'est exactement la signature de la politique SysCallX64,
et le processus est tue avec 0xC0000005.

Le spoofing de la seule adresse de retour a ete teste d'abord : le
processus etait quand meme tue. La mitigation ne regarde pas que la valeur
sur la pile, elle voit aussi ou l'instruction syscall s'execute
physiquement.

Le patch appelle le pointeur de prologue en cache directement depuis le
dispatcher :

```rust
if let Some(target) = direct_call {
    let direct_fn: ABStubFn = unsafe { std::mem::transmute(target) };
    direct_fn(regs[0], regs[1], ...);
}
```

Le syscall s'execute alors dans le .text de ntdll, et le noyau retourne
dans le .text d'activebreach.dll, un module reel. Les deux conditions de
l'heuristique sont invalidees : execution dans un module reel, retour dans
un module reel. Le pointeur en cache est revalide avant chaque appel
(toujours dans la plage du .text de ntdll) pour ne pas utiliser
silencieusement un hook ajoute a l'execution.

## Comment le bypass a ete trouve

### Phase 1 : pourquoi ca bloque

Premiere execution du POC (build release) : le process affiche
"activebreach_launch() retourne : 0" puis se bloque indefiniment sur
l'appel syscall, sans message, CPU a 0%. Le guide upstream affirme que
launch() retournant 0 est un succes. C'est faux : en build release, AbErr()
retourne 0 pour chaque type d'erreur (comportement upstream dans
diagnostics.rs), donc l'echec d'init etait indistinguable d'un succes et le
POC est alle appeler ab_call sans dispatcher en cours d'execution.

System Informer sur le process bloque :

- un seul thread actif (le thread principal), en attente dans
  ntdll!WaitOnAddress, appele depuis activebreach.dll!ab_call
- aucun thread dispatcher dans activebreach.dll, alors que le mecanisme en
  exige un
- trois threads SophosED.dll injectes dans le processus

Le thread principal attendait correctement une reponse d'un dispatcher qui
n'a jamais demarre. Le blocage est un symptome, pas la cause.

Un build debug a revele l'etat reel immediatement : launch() a retourne
-1076909169 (0xBFCFAB8F) et la derniere ligne de log etait le mapper
ouvrant C:\Windows\System32\ntdll.dll. Le moteur echouait pendant
l'init, juste apres l'ouverture de ntdll, silencieusement. Sans le build
debug, cette erreur serait restee invisible.

De la : dump des stubs avec ReadProcessMemory (table ci-dessus), chaine de
trampoline suivie jmp par jmp jusqu'a SophosED.dll+0x5F710, puis un test
A/B. Desinstallation de Sophos, reboot, meme DLL, meme POC. La sequence
d'init complete est apparue (488 SSN, READONLY, hash 0x17E627DBB9C53E22,
thread dispatcher, stub pool) et le syscall a retourne 256 Ko de liste de
processus. Causalite confirmee.

### Phase 2 : au-dela des hooks, dans l'anti exploit

Le patch 1 (v2) a fait passer l'init sous hooks actifs, hash de table
identique a la machine propre. Puis le processus est mort silencieusement
au moment de l'execution du syscall, code de sortie 0xC0000005.
L'Observateur d'evenements a correle HitmanPro.Alert ID 911 (mitigation
SysCall, politique SysCallX64) avec l'erreur application une seconde plus
tard. Meme PID.

Analyse du mecanisme (details dans la section couche 2 ci-dessus) : le
stub de saut prive est ce qui tue.

### Phase 3 : l'appel direct

D'abord le spoofing de l'adresse de retour, toujours tue. Puis le patch 3 :
appel direct du prologue ntdll en cache depuis le dispatcher, plus le
patch 2 pour que le cache de prologues se remplisse reellement sur ce
build Win11.

Resultat le 17/09/2026, Sophos actif, quatre stubs sur six verifies hooke :

- init complete sous hooks actifs (hash de table 0x17E627DBB9C53E22,
  identique a la machine propre)
- NtQuerySystemInformation execute, 288280 octets de liste de processus
  retournes
- zero alerte dans Sophos Central pendant toute la sequence
- le seul observateur restant est la couche noyau (callbacks Ob/Ps,
  ETW Threat Intelligence), qui voit les allocations et la creation de
  thread mais n'a rien correle en alerte pendant le test

## Environnement de test et resultats

| element | detail |
|---------|--------|
| dates | 16 et 17 septembre 2026 |
| OS | Windows 11 Pro 25H2, build 26200.9445 (x64, VM Proxmox isolee, snapshot avant tests) |
| toolchain | Rust 1.82 (x86_64-pc-windows-msvc), VS Build Tools 2022 |
| EDR sous test | Sophos Endpoint : SophosED.dll + HitmanPro.Alert (Intercept X 2024.1.2.10, Core Agent 2026.2.1.3.0) |
| hooks user mode SophosED | contourne (init complete sous hooks actifs) |
| mitigation SysCallX64 | contourne (appel direct du prologue) |
| alertes Sophos Central | aucune pendant l'init, l'execution du syscall ou la fin du processus |
| telemetrie noyau | dernier observateur en ligne, non correle en alertes |
| hash de table | 0x17E627DBB9C53E22 (identique a la machine propre), 488 SSN |
| resultat POC | NtQuerySystemInformation, ReturnLength 288280 octets |

Preuve d'execution du 17/09/2026 (console Sophos Central sans alerte a
gauche, sortie complete du POC a droite) dans le rapport complet :
Rapport_Evaluation_ABE_Sophos_v2-1.pdf.

## Notes de detection

Le resultat du test n'est pas "Sophos est casse". C'est "les heuristiques
mode utilisateur ne sont pas un controle suffisant". Recommandations
concretes, confirmees par le bypass :

- Stack walking dans les callbacks noyau : les callbacks d'allocation
  memoire et de creation de thread doivent verifier l'adresse de retour.
  Un retour dans une region RX privee sans module associe est la signature
  des syscalls directs ; un appel direct de prologue ntdll depuis un module
  tiers (sans passage par kernelbase/kernel32) est aussi anormal.
  Indetectable depuis le mode utilisateur, visible uniquement depuis le
  noyau.
- Scan memoire de stubs syscall : la signature
  4C 8B D1 B8 xx 00 00 00 0F 05 C3 en dehors de ntdll est un stub maison.
  ABE en cree des dizaines dans son pool. Detection simple, tres peu de
  faux positifs. L'upstream fournit exactement ca dans E900U.yar.
- Integrite des propres hooks : l'EDR connait l'octet qu'il a ecrit (E9)
  au debut de ses stubs hookees. Toute restauration ou remplacement doit
  lever une alerte immediatement.
- Correler la telemetrie noyau existante (ETW TI, callbacks Ob/Ps) en
  alertes visibles. Le fait marquant de ce test : rien de cette telemetrie
  ne s'est transforme en alerte sur la console pendant toute la sequence.
- HVCI / VBS et l'integrite du code noyau rendent la creation et
  l'execution de stubs prives nettement plus couteuses pour l'attaquant.

## Build

### DLL (SDK/Rust)

```powershell
cd SDK\Rust

# debug (recommande pour les tests : les vrais codes d'erreur sont logs)
cargo build --features ntdll_backend

# release
cargo build --release --features ntdll_backend
```

Note : en build release, toute erreur d'init est retournee 0 par AbErr()
(comportement upstream, non modifie ici). Toujours verifier la valeur de
retour de activebreach_launch() et tester en debug d'abord.

Sortie attendue a l'init reussie :

```
[AB:MAPPER]  Opening C:\Windows\System32\ntdll.dll
[AB:EXPORTS] SYSCALL_TABLE initialized @0x... (entries=488)
[AB:EXPORTS] SYSCALL_TABLE set to READONLY
[AB:EXPORTS] SYSCALL_TABLE hash = 0x17E627DBB9C53E22
[AB:DISPATCH] dispatcher thread started
[AB:STUB] stub pool ready
```

### POC (dossier poc/)

Charge activebreach.dll avec libloading, verifie la valeur de retour de
launch(), puis emet NtQuerySystemInformation (classe 5,
SystemProcessInformation) via ab_call avec un buffer de 1 Mo. Le syscall
est emis par nom ; le dispatcher resout le SSN et le prologue depuis la
table de syscalls.

```powershell
cd poc
cargo build --release
# placer activebreach.dll a cote de l'executable
# (une DLL pre-compilee est incluse dans le repo, ~288 Ko)
```

Sortie attendue sous Sophos actif :

```
[*] Lancement d'ActiveBreach...
[+] activebreach_launch() retourne : 0
[*] Appel NtQuerySystemInformation via ABE...
[AB:DISPATCH][L3] appel direct du prologue ntdll
[+] SUCCES ! Syscall execute sans detection.
ReturnLength = 288280 octets
[*] POC termine.
```

## Structure du repo

- `SDK/Rust/` : SDK Rust modifie (les trois patches sont dans
  `src/internal/vm.rs`, `src/internal/exports.rs`,
  `src/internal/dispatch.rs`, grep sur `[PATCH`)
- `poc/` : loader POC (Rust, libloading), inclut une activebreach.dll
  pre-compilee
- `E900U.yar` : ruleset YARA public upstream pour detecter ABE en memoire
- `Diagram/` : diagrammes d'architecture upstream
- `Rapport_Evaluation_ABE_Sophos_v2-1.pdf` : rapport d'evaluation complet
  (diagnostic, attribution, test A/B, les trois phases de contournement,
  recommandations detection)

## Limites connues

- Ce fork ne vise que la couche mode utilisateur (hooks SophosED et
  SysCallX64). Les callbacks noyau (Ob/Ps) et ETW Threat Intelligence
  continuent d'observer les allocations memoire et les creations de thread.
  Rien n'a ete correle en alerte sur la console pendant le test, mais la
  telemetrie existe.
- Si aucun prologue sain n'est en cache pour un syscall donne, le
  dispatcher retombe sur le stub prive et peut toujours etre tue par
  SysCallX64.
- Le patch 1 fait passer l'allocation initiale par l'API Win32, donc cette
  allocation est visible de quiconque regarde les callbacks noyau. C'est un
  compromis delibere pour mesurer l'appui de l'EDR sur ses hooks mode
  utilisateur.
- Reaction post-execution non qualifiee : le processus se termine avec
  0xC0000005 apres l'affichage de "POC termine." (aucun evenement dans la
  console Sophos, resultat non affecte).
- Les SDK C et C++ ne sont pas patches (Rust uniquement).

## Credits

- ABE original : [8damon/ActiveBreach-Engine](https://github.com/8damon/ActiveBreach-Engine),
  copyright 2026 RYFTENIUS, licence Apache 2.0 avec Commons Clause
  (pas d'usage commercial).
- Analyse des hooks et technique du stub relocalise : Signal Labs,
  "In-Memory Disassembly for EDR/AV Unhooking", avril 2023.
  https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/
  Code d'exemple : https://github.com/Signal-Labs/iat_unhook_sample
- Patches, POC et rapport d'evaluation : 0xKuraishY, septembre 2026.

## Avertissement

Cet outil est destine a la recherche en securite offensive et a l'evaluation
de la resilience des EDR, dans un environnement de laboratoire isole et avec
une autorisation explicite. Ne pas le deployer sur des systemes hors
perimetre autorise.
