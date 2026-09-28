use std::ptr;
fn main() {
    unsafe {
        let lib = libloading::Library::new("activebreach.dll")
            .expect("[-] Failed to load activebreach.dll");

        let launch: libloading::Symbol<unsafe extern "C" fn() -> i32> =
            lib.get(b"activebreach_launch\0")
                .expect("[-] Symbol activebreach_launch not found");

        println!("[*] Launching ActiveBreach...");
        let ret = launch();
        if ret != 0 {
            println!("[-] launch() FAILED: {:#x} - aborting.", ret);
            return;
        }
        println!("[+] activebreach_launch() returned: {}", ret);

        let ab_call: libloading::Symbol<
            unsafe extern "C" fn(*const u8, *const usize, usize) -> usize,
        > = lib
            .get(b"ab_call\0")
            .expect("[-] Symbol ab_call not found");

        let mut buffer = vec![0u8; 1024 * 1024];
        let mut return_length: usize = 0;
        let info_class: usize = 5;
        
        let args: [usize; 4] = [
            info_class,                                  // SystemInformationClass
            buffer.as_mut_ptr() as usize,                // SystemInformation
            buffer.len(),                                // SystemInformationLength
            &mut return_length as *mut usize as usize,   // ReturnLength
        ];

        println!("[*] Calling NtQuerySystemInformation via ABE...");
        let status = ab_call(
            "NtQuerySystemInformation\0".as_ptr(),
            args.as_ptr(),
            args.len(),
        );

        if status == 0 {
            println!("[+] SUCCESS! Syscall executed without detection.");
            println!("ReturnLength = {} bytes", return_length);

            // Parse the process list straight from the kernel buffer
            #[repr(C)]
            struct UniStr { len: u16, max: u16, _pad: u32, buf: *const u16 }

            let mut off = 0usize;
            let mut n = 0;
            loop {
                let base = unsafe { buffer.as_ptr().add(off) };
                let next = unsafe { *(base as *const u32) } as usize;
                let img = unsafe { &*(base.add(0x38) as *const UniStr) };
                if !img.buf.is_null() && img.len > 0 {
                    let w = unsafe { std::slice::from_raw_parts(img.buf, (img.len / 2) as usize) };
                    let name: String = w.iter().map(|&c| char::from_u32(c as u32).unwrap_or('?')).collect();
                    println!("  [{:>3}] {}", n, name);
                    n += 1;
                }
                if next == 0 { break; }
                off += next;
            }
            println!("[+] {} processes read via direct syscall.", n);
        } else {
            println!("[-] NTSTATUS failure: {:#x}", status);
        }

        println!("[*] POC finished.");
    }
}