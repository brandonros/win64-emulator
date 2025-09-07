/*
NtSetInformationThread function (ntifs.h)
07/28/2022
The NtSetInformationThread routine sets the priority of a thread.

Syntax
C++

Copy
__kernel_entry NTSYSCALLAPI NTSTATUS NtSetInformationThread(
  [in] HANDLE          ThreadHandle,
  [in] THREADINFOCLASS ThreadInformationClass,
  [in] PVOID           ThreadInformation,
  [in] ULONG           ThreadInformationLength
);
Parameters
[in] ThreadHandle

Handle to the thread object. To create a new thread and get a handle to it, call PsCreateSystemThread. To specify the current thread, use the ZwCurrentThread macro.

[in] ThreadInformationClass

One of the system-defined values in the THREADINFOCLASS enumeration (see ntddk.h), ThreadPriority, ThreadBasePriority, ThreadPagePriority, or ThreadPowerThrottlingState.

[in] ThreadInformation

Pointer to a variable that specifies the information to set.

If ThreadInformationClass is ThreadPriority, this value must be > LOW_PRIORITY and <= HIGH_PRIORITY.

If ThreadInformationClass is ThreadBasePriority, this value must fall within the system's valid base-priority range and the original priority class for the given thread. That is, if a thread's priority class is variable, that thread's base priority cannot be reset to a real-time priority value, and vice versa.

If ThreadInformationClass is ThreadPagePriority, this value is a pointer to a PAGE_PRIORITY_INFORMATION structure, see ntddk.h. The PagePriority member value must be one of these values.

If ThreadInformationClass is ThreadPowerThrottlingState, this value is a pointer to a POWER_THROTTLING_THREAD_STATE structure, see ntddk.h. The PagePriority member value must be one of these values.

Value	Meaning
MEMORY_PRIORITY_VERY_LOW (1)	Very low memory priority.
MEMORY_PRIORITY_LOW (2)	Low memory priority.
MEMORY_PRIORITY_MEDIUM (3)	Medium memory priority.
MEMORY_PRIORITY_BELOW_NORMAL (4)	Below normal memory priority.
MEMORY_PRIORITY_NORMAL (5)	Normal memory priority. This is the default priority for all threads and processes on the system.
[in] ThreadInformationLength

The size, in bytes, of ThreadInformation.

Return value
NtSetInformationThread returns STATUS_SUCCESS on success, or the appropriate NTSTATUS error code on failure. Possible error codes include STATUS_INFO_LENGTH_MISMATCH or STATUS_INVALID_PARAMETER.

Remarks
NtSetInformationThread can be called by higher-level drivers to set the priority of a thread for which they have a handle.

The caller must have THREAD_SET_INFORMATION access rights for the given thread in order to call this routine.

Usually, device and intermediate drivers that set up driver-created threads call KeSetBasePriorityThread or KeSetPriorityThread from their driver-created threads, rather than calling NtSetInformationThread. However, a driver can call NtSetInformationThread to raise the priority of a driver-created thread before that thread runs.

Kernel mode drivers can call the NtSetInformationThread function with ThreadPagePriority to specify a thread's page priority.

To help improve system performance, drivers should use the function with ThreadPagePriority to lower the page priority of threads that perform background operations or access files and data that are not expected to be accessed again soon. For example, an anti-malware application might lower the priority of threads involved in scanning files.

 Note

If the call to this function occurs in kernel mode, you should use the name ZwSetInformationThread instead of NtSetInformationThread.

For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine can behave differently in the way that they handle and interpret input parameters. For more information about the relationship between the NtXxx and ZwXxx versions of a routine, see Using Nt and Zw Versions of the Native System Services Routines..
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn NtSetInformationThread(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // NTSTATUS NtSetInformationThread(
    //   HANDLE          ThreadHandle,            // RCX
    //   THREADINFOCLASS ThreadInformationClass,  // RDX
    //   PVOID           ThreadInformation,       // R8
    //   ULONG           ThreadInformationLength  // R9
    // )
    
    let thread_handle = emu.reg_read(X86Register::RCX)?;
    let info_class = emu.reg_read(X86Register::RDX)?;
    let info_ptr = emu.reg_read(X86Register::R8)?;
    let info_length = emu.reg_read(X86Register::R9)? as u32;
    
    // NTSTATUS constants
    const STATUS_SUCCESS: u32 = 0x00000000;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC0000004;
    const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
    
    // Common THREADINFOCLASS values
    const THREAD_PRIORITY: u32 = 0;
    const THREAD_BASE_PRIORITY: u32 = 1;
    const THREAD_AFFINITY_MASK: u32 = 4;
    const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;
    const THREAD_PAGE_PRIORITY: u32 = 0x1C;
    const THREAD_POWER_THROTTLING_STATE: u32 = 0x31;
    
    log::info!(
        "[NtSetInformationThread] ThreadHandle: 0x{:x}, InfoClass: {}, InfoPtr: 0x{:x}, InfoLength: {}",
        thread_handle, info_class, info_ptr, info_length
    );
    
    // Check for null handle
    if thread_handle == 0 {
        log::error!("[NtSetInformationThread] NULL handle provided");
        emu.reg_write(X86Register::RAX, STATUS_INVALID_HANDLE as u64)?;
        return Ok(());
    }
    
    // Handle different information classes
    match info_class as u32 {
        THREAD_PRIORITY => {
            // ThreadPriority expects a KPRIORITY (LONG)
            if info_length != 4 {
                log::error!("[NtSetInformationThread] Invalid length for ThreadPriority: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut priority_bytes = [0u8; 4];
            emu.mem_read(info_ptr, &mut priority_bytes)?;
            let priority = i32::from_le_bytes(priority_bytes);
            
            log::info!("[NtSetInformationThread] Setting thread priority to {} (mock)", priority);
        }
        
        THREAD_BASE_PRIORITY => {
            // ThreadBasePriority expects a LONG
            if info_length != 4 {
                log::error!("[NtSetInformationThread] Invalid length for ThreadBasePriority: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut priority_bytes = [0u8; 4];
            emu.mem_read(info_ptr, &mut priority_bytes)?;
            let base_priority = i32::from_le_bytes(priority_bytes);
            
            log::info!("[NtSetInformationThread] Setting thread base priority to {} (mock)", base_priority);
        }
        
        THREAD_HIDE_FROM_DEBUGGER => {
            // ThreadHideFromDebugger doesn't require any data
            if info_ptr != 0 || info_length != 0 {
                log::warn!("[NtSetInformationThread] ThreadHideFromDebugger expects null info");
            }
            
            log::info!("[NtSetInformationThread] Hiding thread from debugger (mock)");
        }
        
        THREAD_AFFINITY_MASK => {
            // ThreadAffinityMask expects a KAFFINITY (ULONG_PTR on 64-bit)
            if info_length != 8 {
                log::error!("[NtSetInformationThread] Invalid length for ThreadAffinityMask: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut affinity_bytes = [0u8; 8];
            emu.mem_read(info_ptr, &mut affinity_bytes)?;
            let affinity = u64::from_le_bytes(affinity_bytes);
            
            log::info!("[NtSetInformationThread] Setting thread affinity mask to 0x{:x} (mock)", affinity);
        }
        
        THREAD_PAGE_PRIORITY => {
            // ThreadPagePriority expects a PAGE_PRIORITY_INFORMATION structure
            if info_length < 4 {
                log::error!("[NtSetInformationThread] Invalid length for ThreadPagePriority: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut page_priority_bytes = [0u8; 4];
            emu.mem_read(info_ptr, &mut page_priority_bytes)?;
            let page_priority = u32::from_le_bytes(page_priority_bytes);
            
            log::info!("[NtSetInformationThread] Setting thread page priority to {} (mock)", page_priority);
        }
        
        THREAD_QUERY_SET_WIN32_START_ADDRESS => {
            // Win32StartAddress expects a PVOID
            if info_length != 8 {
                log::error!("[NtSetInformationThread] Invalid length for Win32StartAddress: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut address_bytes = [0u8; 8];
            emu.mem_read(info_ptr, &mut address_bytes)?;
            let start_address = u64::from_le_bytes(address_bytes);
            
            log::info!("[NtSetInformationThread] Setting Win32 start address to 0x{:x} (mock)", start_address);
        }
        
        THREAD_IMPERSONATION_TOKEN => {
            // ThreadImpersonationToken expects a HANDLE
            if info_length != 8 {
                log::error!("[NtSetInformationThread] Invalid length for ImpersonationToken: {}", info_length);
                emu.reg_write(X86Register::RAX, STATUS_INFO_LENGTH_MISMATCH as u64)?;
                return Ok(());
            }
            
            let mut token_bytes = [0u8; 8];
            emu.mem_read(info_ptr, &mut token_bytes)?;
            let token_handle = u64::from_le_bytes(token_bytes);
            
            log::info!("[NtSetInformationThread] Setting impersonation token to 0x{:x} (mock)", token_handle);
        }
        
        _ => {
            log::warn!("[NtSetInformationThread] Unsupported ThreadInformationClass: {}", info_class);
            // For unknown classes, just log and return success
        }
    }
    
    // Return STATUS_SUCCESS
    emu.reg_write(X86Register::RAX, STATUS_SUCCESS as u64)?;
    
    log::info!("[NtSetInformationThread] Returning STATUS_SUCCESS");
    
    Ok(())
}