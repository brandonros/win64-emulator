use unicorn_engine::{Unicorn, RegisterX86};
use std::sync::atomic::{AtomicU64, Ordering};

/*
CreateToolhelp32Snapshot function (tlhelp32.h)
10/12/2021
Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

Syntax
C++

Copy
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
Parameters
[in] dwFlags

The portions of the system to be included in the snapshot. This parameter can be one or more of the following values.

Value	Meaning
TH32CS_INHERIT
0x80000000
Indicates that the snapshot handle is to be inheritable.
TH32CS_SNAPALL
Includes all processes and threads in the system, plus the heaps and modules of the process specified in th32ProcessID. Equivalent to specifying the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, and TH32CS_SNAPTHREAD values combined using an OR operation ('|').
TH32CS_SNAPHEAPLIST
0x00000001
Includes all heaps of the process specified in th32ProcessID in the snapshot. To enumerate the heaps, see Heap32ListFirst.
TH32CS_SNAPMODULE
0x00000008
Includes all modules of the process specified in th32ProcessID in the snapshot. To enumerate the modules, see Module32First. If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds.
64-bit Windows:  Using this flag in a 32-bit process includes the 32-bit modules of the process specified in th32ProcessID, while using it in a 64-bit process includes the 64-bit modules. To include the 32-bit modules of the process specified in th32ProcessID from a 64-bit process, use the TH32CS_SNAPMODULE32 flag.

TH32CS_SNAPMODULE32
0x00000010
Includes all 32-bit modules of the process specified in th32ProcessID in the snapshot when called from a 64-bit process. This flag can be combined with TH32CS_SNAPMODULE or TH32CS_SNAPALL. If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds.
TH32CS_SNAPPROCESS
0x00000002
Includes all processes in the system in the snapshot. To enumerate the processes, see Process32First.
TH32CS_SNAPTHREAD
0x00000004
Includes all threads in the system in the snapshot. To enumerate the threads, see Thread32First.
To identify the threads that belong to a specific process, compare its process identifier to the th32OwnerProcessID member of the THREADENTRY32 structure when enumerating the threads.

[in] th32ProcessID

The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.

If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

If the specified process is a 64-bit process and the caller is a 32-bit process, this function fails and the last error code is ERROR_PARTIAL_COPY (299).

Return value
If the function succeeds, it returns an open handle to the specified snapshot.

If the function fails, it returns INVALID_HANDLE_VALUE. To get extended error information, call GetLastError. Possible error codes include ERROR_BAD_LENGTH.
*/

// Snapshot flags constants
const TH32CS_INHERIT: u32 = 0x80000000;
const TH32CS_SNAPHEAPLIST: u32 = 0x00000001;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const TH32CS_SNAPTHREAD: u32 = 0x00000004;
const TH32CS_SNAPMODULE: u32 = 0x00000008;
const TH32CS_SNAPMODULE32: u32 = 0x00000010;
const TH32CS_SNAPALL: u32 = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD;

// Snapshot handle counter - starts at a non-zero value
static SNAPSHOT_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(0x30000);

pub fn CreateToolhelp32Snapshot(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HANDLE CreateToolhelp32Snapshot(
    //   [in] DWORD dwFlags,       // RCX
    //   [in] DWORD th32ProcessID  // RDX
    // )
    
    let dw_flags = emu.reg_read(RegisterX86::RCX)? as u32;
    let th32_process_id = emu.reg_read(RegisterX86::RDX)? as u32;
    
    log::info!("[CreateToolhelp32Snapshot] dwFlags: 0x{:x}", dw_flags);
    log::info!("[CreateToolhelp32Snapshot] th32ProcessID: 0x{:x}", th32_process_id);
    
    // Log which flags are set
    if dw_flags & TH32CS_INHERIT != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_INHERIT is set");
    }
    if dw_flags & TH32CS_SNAPHEAPLIST != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_SNAPHEAPLIST is set");
    }
    if dw_flags & TH32CS_SNAPPROCESS != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_SNAPPROCESS is set");
    }
    if dw_flags & TH32CS_SNAPTHREAD != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_SNAPTHREAD is set");
    }
    if dw_flags & TH32CS_SNAPMODULE != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_SNAPMODULE is set");
    }
    if dw_flags & TH32CS_SNAPMODULE32 != 0 {
        log::info!("[CreateToolhelp32Snapshot] Flag TH32CS_SNAPMODULE32 is set");
    }
    
    // Check if TH32CS_SNAPALL is effectively set
    if (dw_flags & TH32CS_SNAPALL) == TH32CS_SNAPALL {
        log::info!("[CreateToolhelp32Snapshot] All snapshot flags are set (TH32CS_SNAPALL)");
    }
    
    // Check for invalid flags
    if dw_flags == 0 {
        log::error!("[CreateToolhelp32Snapshot] No flags specified");
        emu.reg_write(RegisterX86::RAX, 0xFFFFFFFFFFFFFFFF)?; // INVALID_HANDLE_VALUE
        return Ok(());
    }
    
    // Special process IDs
    if th32_process_id == 0 {
        log::info!("[CreateToolhelp32Snapshot] Process ID 0 - using current process");
    } else if th32_process_id == 4 {
        // System process (often used by anti-debugging)
        log::warn!("[CreateToolhelp32Snapshot] Attempting to snapshot System process (PID 4)");
    }
    
    // Generate a new snapshot handle
    let snapshot_handle = SNAPSHOT_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    
    log::info!("[CreateToolhelp32Snapshot] Created snapshot handle: 0x{:x}", snapshot_handle);
    
    // Store snapshot information for later use by Process32First/Next, Module32First/Next, etc.
    // In a real implementation, we would store the snapshot data structure
    // For now, we just return a mock handle
    
    log::warn!("[CreateToolhelp32Snapshot] Mock implementation - returning snapshot handle");
    log::info!("[CreateToolhelp32Snapshot] Snapshot includes:");
    if dw_flags & TH32CS_SNAPPROCESS != 0 {
        log::info!("  - Process list");
    }
    if dw_flags & TH32CS_SNAPTHREAD != 0 {
        log::info!("  - Thread list");
    }
    if dw_flags & TH32CS_SNAPMODULE != 0 {
        log::info!("  - Module list (64-bit)");
    }
    if dw_flags & TH32CS_SNAPMODULE32 != 0 {
        log::info!("  - Module list (32-bit)");
    }
    if dw_flags & TH32CS_SNAPHEAPLIST != 0 {
        log::info!("  - Heap list");
    }
    
    // Return the snapshot handle
    emu.reg_write(RegisterX86::RAX, snapshot_handle)?;
    
    Ok(())
}