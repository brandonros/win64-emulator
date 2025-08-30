use unicorn_engine::{Unicorn, RegisterX86};

/*
ZwClose function (wdm.h)
01/13/2023
The ZwClose routine closes an object handle.

Syntax
C++

Copy
NTSYSAPI NTSTATUS ZwClose(
  [in] HANDLE Handle
);
Parameters
[in] Handle

Handle to an object of any type.

Return value
ZwClose returns STATUS_SUCCESS on success, or the appropriate NTSTATUS error code on failure. In particular, it returns STATUS_INVALID_HANDLE if Handle is not a valid handle, or STATUS_HANDLE_NOT_CLOSABLE if the calling thread does not have permission to close the handle.

Remarks
ZwClose is a generic routine that operates on any type of object.

Closing an open object handle causes that handle to become invalid. The system also decrements the handle count for the object and checks whether the object can be deleted. The system does not actually delete the object until all of the object's handles are closed and no referenced pointers remain.

A driver must close every handle that it opens as soon as the handle is no longer required. Kernel handles, which are those that are opened by a system thread or by specifying the OBJ_KERNEL_HANDLE flag, can be closed only when the previous processor mode is KernelMode. This requirement applies both to system threads and to dispatch routines for IRPs that were issued from kernel mode. (For more information about the previous processor mode, see ExGetPreviousMode.) For example, a handle that ZwCreateKey returns to a DriverEntry routine cannot subsequently be closed by the same driver's dispatch routines. A DriverEntry routine runs in a system process, whereas dispatch routines usually run either in the context of the thread issuing the current I/O request, or, for lower-level drivers, in an arbitrary thread context.

A non-kernel handle can be closed only if one of two conditions is met: The previous processor mode is KernelMode, or the calling thread has sufficient permission to close the handle. An example of the latter occurs when the calling thread is the one that created the handle.

Callers of ZwClose should not assume that this routine automatically waits for all I/O to complete prior to returning.

If the call to this function occurs in user mode, you should use the name "NtClose" instead of "ZwClose".

For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine can behave differently in the way that they handle and interpret input parameters. For more information about the relationship between the NtXxx and ZwXxx versions of a routine, see Using Nt and Zw Versions of the Native System Services Routines.
*/

pub fn ZwClose(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // NTSTATUS ZwClose(
    //   [in] HANDLE Handle  // RCX
    // )
    
    let handle = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[ZwClose] Handle: 0x{:x}", handle);
    
    // NTSTATUS constants
    const STATUS_SUCCESS: u32 = 0x00000000;
    const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
    
    // Check for invalid handle (NULL)
    if handle == 0 {
        log::error!("[ZwClose] Invalid handle (NULL)");
        emu.reg_write(RegisterX86::RAX, STATUS_INVALID_HANDLE as u64)?;
        return Ok(());
    }
    
    log::info!("[ZwClose] Closed handle 0x{:x} successfully", handle);
    log::warn!("[ZwClose] Mock implementation - handle not actually closed");
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, STATUS_SUCCESS as u64)?;
    
    Ok(())
}