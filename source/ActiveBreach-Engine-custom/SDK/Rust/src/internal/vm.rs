
use std::sync::OnceLock;

use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAlloc, VirtualFree,
    VirtualProtect,
};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::internal::stack::{AbGetModuleBasePeb, AbResolveNtdllStub};

type ULONG = u32;
type UlongPtr = usize;
type SizeT = usize;
type PVOID = *mut core::ffi::c_void;

type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: UlongPtr,
    RegionSize: *mut SizeT,
    AllocationType: ULONG,
    Protect: ULONG,
) -> NTSTATUS;

type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: *mut SizeT,
    NewProtect: ULONG,
    OldProtect: *mut ULONG,
) -> NTSTATUS;

type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: *mut SizeT,
    FreeType: ULONG,
) -> NTSTATUS;

static NTDLL_TEXT: OnceLock<(usize, usize)> = OnceLock::new();
static NT_ALLOC_PRO: OnceLock<usize> = OnceLock::new();
static NT_PROTECT_PRO: OnceLock<usize> = OnceLock::new();
static NT_FREE_PRO: OnceLock<usize> = OnceLock::new();

#[inline(always)]
fn nt_success(st: NTSTATUS) -> bool {
    st.0 >= 0
}

fn ntdll_text_range() -> Option<(usize, usize)> {
    let (start, end) = *NTDLL_TEXT.get_or_init(|| unsafe {
        let base = match AbGetModuleBasePeb("NTDLL.DLL") {
            Some(b) => b,
            None => return (0, 0),
        };

        let dos = &*(base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return (0, 0);
        }

        let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt.Signature != 0x0000_4550 {
            return (0, 0);
        }

        let num_secs = nt.FileHeader.NumberOfSections as usize;
        let sec_ptr = (nt as *const _ as usize + core::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        let secs = core::slice::from_raw_parts(sec_ptr, num_secs);

        for s in secs {
            if s.Name[..5] == [b'.', b't', b'e', b'x', b't'] {
                let s_start = base + s.VirtualAddress as usize;
                let s_size = s.Misc.VirtualSize as usize;
                let s_end = s_start.saturating_add(s_size);
                return (s_start, s_end);
            }
        }

        (0, 0)
    });

    if start == 0 || end <= start {
        None
    } else {
        Some((start, end))
    }
}

#[inline(always)]
fn find_syscall_prologue_offset(code: &[u8]) -> Option<usize> {
    let scan_len = code.len().min(96);
    let code = &code[..scan_len];

    for i in 0..code.len().saturating_sub(11) {
        let head = &code[i..];
        let has_mov = head.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8])
            || head.starts_with(&[0x4D, 0x8B, 0xD1, 0xB8]);
        if !has_mov {
            continue;
        }

        let end = code.len().min(i + 64);
        for j in (i + 4)..end.saturating_sub(2) {
            if code[j] == 0x0F && code[j + 1] == 0x05 && code[j + 2] == 0xC3 {
                return Some(i);
            }
        }
    }

    None
}

fn resolve_ntdll_prologue(nt_name: &str) -> Option<usize> {
    let (tstart, tend) = ntdll_text_range()?;
    let entry = AbResolveNtdllStub(nt_name)? as usize;

    const SCAN_LEN: usize = 96;
    if entry < tstart || entry.checked_add(SCAN_LEN).is_none_or(|e| e > tend) {
        return None;
    }

    let code = unsafe { core::slice::from_raw_parts(entry as *const u8, SCAN_LEN) };
    let off = find_syscall_prologue_offset(code)?;
    Some(entry + off)
}

pub fn AbResolveNtdllSyscallPrologue(nt_name: &str) -> Option<usize> {
    resolve_ntdll_prologue(nt_name)
}

#[inline(always)]
fn nt_allocate_prologue() -> Option<usize> {
    if let Some(p) = NT_ALLOC_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtAllocateVirtualMemory")?;
    let _ = NT_ALLOC_PRO.set(p);
    Some(p)
}

#[inline(always)]
fn nt_protect_prologue() -> Option<usize> {
    if let Some(p) = NT_PROTECT_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtProtectVirtualMemory")?;
    let _ = NT_PROTECT_PRO.set(p);
    Some(p)
}

#[inline(always)]
fn nt_free_prologue() -> Option<usize> {
    if let Some(p) = NT_FREE_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtFreeVirtualMemory")?;
    let _ = NT_FREE_PRO.set(p);
    Some(p)
}

#[inline(always)]
fn fallback_alloc(size: usize, protect: u32) -> *mut u8 {
    let p = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_PROTECTION_FLAGS(protect)) };
    if p.is_null() { core::ptr::null_mut() } else { p as *mut u8 }
}

#[inline(always)]
fn fallback_protect(addr: *mut u8, len: usize, new_protect: u32, old_protect: &mut u32) -> bool {
    let mut old: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
    let ok = unsafe {
        VirtualProtect(
            addr as *const core::ffi::c_void,
            len,
            PAGE_PROTECTION_FLAGS(new_protect),
            &mut old as *mut PAGE_PROTECTION_FLAGS,
        )
    };
    *old_protect = old.0;
    ok.is_ok()
}

#[inline(always)]
fn fallback_free(addr: *mut u8) -> bool {
    unsafe { VirtualFree(addr as *mut core::ffi::c_void, 0, MEM_RELEASE).is_ok() }
}

pub unsafe fn AbVirtualAlloc(size: usize, protect: u32) -> *mut u8 {
    if let Some(pro) = nt_allocate_prologue() {
        let f: NtAllocateVirtualMemoryFn = core::mem::transmute(pro as *const u8);
        let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
        let mut base: PVOID = core::ptr::null_mut();
        let mut region: SizeT = size;

        let st = f(
            proc,
            &mut base as *mut PVOID,
            0,
            &mut region as *mut SizeT,
            (MEM_COMMIT | MEM_RESERVE).0,
            protect,
        );

        if nt_success(st) && !base.is_null() {
            return base as *mut u8;
        }
    }

    fallback_alloc(size, protect)
}

pub unsafe fn AbVirtualProtect(addr: *mut u8, len: usize, new_protect: u32, old_protect: &mut u32) -> bool {
    if let Some(pro) = nt_protect_prologue() {
        let f: NtProtectVirtualMemoryFn = core::mem::transmute(pro as *const u8);
        let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
        let mut base: PVOID = addr as PVOID;
        let mut region: SizeT = len;
        let mut old: ULONG = 0;

        let st = f(
            proc,
            &mut base as *mut PVOID,
            &mut region as *mut SizeT,
            new_protect,
            &mut old as *mut ULONG,
        );

        if nt_success(st) {
            *old_protect = old;
            return true;
        }
    }

    fallback_protect(addr, len, new_protect, old_protect)
}

pub unsafe fn AbVirtualFree(addr: *mut u8) -> bool {
    if let Some(pro) = nt_free_prologue() {
        let f: NtFreeVirtualMemoryFn = core::mem::transmute(pro as *const u8);
        let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
        let mut base: PVOID = addr as PVOID;
        let mut region: SizeT = 0;

        let st = f(
            proc,
            &mut base as *mut PVOID,
            &mut region as *mut SizeT,
            MEM_RELEASE.0,
        );

        if nt_success(st) {
            return true;
        }
    }

    fallback_free(addr)
}