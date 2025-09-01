/*
SetThreadStackGuarantee function (processthreadsapi.h)
02/06/2024
Sets the minimum size of the stack associated with the calling thread or fiber that will be available during any stack overflow exceptions. This is useful for handling stack overflow exceptions; the application can safely use the specified number of bytes during exception handling.

Syntax
C++

Copy
BOOL SetThreadStackGuarantee(
  [in, out] PULONG StackSizeInBytes
);
Parameters
[in, out] StackSizeInBytes

The size of the stack, in bytes. On return, this value is set to the size of the previous stack, in bytes.

If this parameter is 0 (zero), the function succeeds and the parameter contains the size of the current stack.

If the specified size is less than the current size, the function succeeds but ignores this request. Therefore, you cannot use this function to reduce the size of the stack.

This value cannot be larger than the reserved stack size.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
*/

use unicorn_engine::{Unicorn, RegisterX86};

// Default stack guarantee size (4KB is typical)
const DEFAULT_STACK_GUARANTEE: u32 = 0x1000;

pub fn SetThreadStackGuarantee(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL SetThreadStackGuarantee(
    //   [in, out] PULONG StackSizeInBytes  // RCX - pointer to ULONG
    // );
    
    let stack_size_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    if stack_size_ptr == 0 {
        log::warn!("[SetThreadStackGuarantee] NULL pointer provided, returning FALSE");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }
    
    // Read the requested stack size
    let mut size_bytes = [0u8; 4];
    emu.mem_read(stack_size_ptr, &mut size_bytes)?;
    let requested_size = u32::from_le_bytes(size_bytes);
    
    log::info!("[SetThreadStackGuarantee] StackSizeInBytes ptr: 0x{:x}, requested size: 0x{:x}", 
              stack_size_ptr, requested_size);
    
    // Mock implementation - always use a default guarantee size
    let previous_size = DEFAULT_STACK_GUARANTEE;
    
    // Write the previous size back to the pointer
    emu.mem_write(stack_size_ptr, &previous_size.to_le_bytes())?;
    
    if requested_size == 0 {
        // Just querying current size
        log::info!("[SetThreadStackGuarantee] Query mode - returning current size: 0x{:x}", 
                  previous_size);
    } else if requested_size < previous_size {
        // Can't reduce size - ignore but succeed
        log::info!("[SetThreadStackGuarantee] Requested size 0x{:x} < current 0x{:x}, ignoring", 
                  requested_size, previous_size);
    } else {
        // Would set new size in real implementation
        log::info!("[SetThreadStackGuarantee] Mock: Would set stack guarantee to 0x{:x}", 
                  requested_size);
    }
    
    // Return TRUE (success)
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    log::info!("[SetThreadStackGuarantee] Returning TRUE with previous size: 0x{:x}", 
              previous_size);
    
    Ok(())
}