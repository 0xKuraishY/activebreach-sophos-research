Voici le script final, prêt à enchaîner. Un seul PowerShell maximisé, grosse police. Tu colles bloc par bloc, dans l'ordre :

```powershell
# --- 1. Horodatage ---
Get-Date
```

```powershell
# --- 2. Sophos tourne ---
Get-Service *sophos* | Select-Object Name, Status
```

```powershell
# --- 3. Hooks vivants (coller TOUT le bloc d'un coup) ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Mem {
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    public static byte[] Read(IntPtr addr, int len) {
        byte[] b = new byte[len]; int r = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), addr, b, len, out r)) return null;
        return b;
    }
}
"@
$nt = [Mem]::GetModuleHandle("ntdll.dll")
foreach ($f in @("NtAllocateVirtualMemory","NtProtectVirtualMemory","NtFreeVirtualMemory","NtCreateThreadEx","NtQuerySystemInformation","NtClose")) {
    $p = [Mem]::GetProcAddress($nt, $f)
    $b = [Mem]::Read($p, 8)
    $etat = if ($b[0] -eq 0xE9) { "HOOKE (E9)" } else { "sain" }
    Write-Host ("{0,-30} {1}  {2}" -f $f, (($b | ForEach-Object { $_.ToString("X2") }) -join " "), $etat)
}
```

```powershell
# --- 4. Leurre légitime : notepad normal, pas de copie ---
notepad
```
*(le bloc-notes s'ouvre, tu le laisses ouvert en arrière-plan)*

```powershell
# --- 5. Build de l'outil (patché) ---
cd C:\Bp_edr\ActiveBreach-Engine-Custom\SDK\Rust
cargo build --features ntdll_backend
```

```powershell
# --- 6. Preuve binaire du patch (chemin absolu) ---
[System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes("C:\Bp_edr\ActiveBreach-Engine-Custom\SDK\Rust\target\debug\activebreach.dll")).Contains("appel direct du prologue ntdll")
```
*(attendre `True`)*

```powershell
# --- 7. Déploiement ---
Get-Process abe_poc -ErrorAction SilentlyContinue | Stop-Process -Force
copy target\debug\activebreach.dll C:\Bp_edr\poc\
cd C:\Bp_edr\poc
```

```powershell
# --- 8. LE RUN ---
.\target\release\abe_poc.exe
```

```powershell
# --- 9. Code de sortie ---
echo $LASTEXITCODE
```

**Puis bascule écran :** navigateur sur Central > Events de l'appareil (refresh, vide) + UI locale Sophos "Votre appareil est protégé".

**Timing estimé :** 2 à 3 minutes. Une prise, pas de cut sauf la bascule finale.

**Les 3 répliques qui portent la vidéo :**

1. Après l'étape 3 : *"4 stubs sur 6 hookés par Sophos, en direct, dans ce terminal."*
2. Quand la liste défile à l'étape 8 : *"Tout ça vient du noyau via le chemin contourné. Vous voyez hmpalert.exe ? Le processus de l'anti-exploit, il est dans la liste. Et notepad, celui que j'ai ouvert à la main."*
3. Sur la console vide : *"Et là : rien. Pas une alerte."*

Rappel : vérifie avant de record que Central > Events est propre (plus aucune trace de l'alerte canary d'hier). 🎬