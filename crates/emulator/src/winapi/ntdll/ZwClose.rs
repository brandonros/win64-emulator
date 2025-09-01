use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::vfs::VIRTUAL_FS;

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
ZwClose returns STATUS_SUCCESS on success, or the appropriate NTSTATUS error code on failure. In particular, it returns STATUS_INVALID_HANDLE if Handle is not a valid handle, or STATUS_HANDLE_NOT_CLOSABLE if the handle cannot be closed.

Remarks
ZwClose is a generic routine that operates on any type of object.

Closing an open object handle causes that handle to become invalid. The system also decrements the handle count for the object and checks whether the object can be deleted. The system does not actually delete the object until all of the object's handles are closed and no referenced pointers remain.

A driver must close every handle that it opens as soon as the handle is no longer required. Kernel handles, which are those that are opened by a system thread or by specifying the OBJ_KERNEL_HANDLE flag, can be closed only in the context of the system process (PsInitialSystemProcess). This restriction does not apply to handles that are created in the context of the System process. For more information, see Object Handles.

Callers of ZwClose should not assume that this routine automatically waits for all I/O to complete prior to returning.

Requirements
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
    const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC0000235;
    
    // Check for null handle
    if handle == 0 {
        log::error!("[ZwClose] NULL handle provided");
        emu.reg_write(RegisterX86::RAX, STATUS_INVALID_HANDLE as u64)?;
        return Ok(());
    }
    
    // Special handles that shouldn't be closed
    // Standard handles: stdin=0x10, stdout=0x14, stderr=0x18
    // Console handles: 0x20, NUL device: 0x30
    if handle == 0x10 || handle == 0x14 || handle == 0x18 || handle == 0x20 || handle == 0x30 {
        log::warn!("[ZwClose] Attempting to close system handle 0x{:x}", handle);
        emu.reg_write(RegisterX86::RAX, STATUS_HANDLE_NOT_CLOSABLE as u64)?;
        return Ok(());
    }
    
    // Try to close handle in VFS
    let closed = {
        let mut vfs = VIRTUAL_FS.write().unwrap();
        vfs.close_handle(handle)
    };
    
    if closed {
        log::info!("[ZwClose] Successfully closed handle 0x{:x}", handle);
        emu.reg_write(RegisterX86::RAX, STATUS_SUCCESS as u64)?;
    } else {
        // Handle might be a non-file handle (event, thread, etc.)
        // For now, just log and return success for unknown handles
        log::info!("[ZwClose] Handle 0x{:x} not found in VFS (might be non-file handle)", handle);
        emu.reg_write(RegisterX86::RAX, STATUS_SUCCESS as u64)?;
    }
    
    Ok(())
}