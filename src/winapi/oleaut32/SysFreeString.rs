use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

/*
SysFreeString function (oleauto.h)
02/22/2024
Deallocates a string allocated previously by SysAllocString, SysAllocStringByteLen, SysReAllocString, SysAllocStringLen, or SysReAllocStringLen.

Syntax
C++

Copy
void SysFreeString(
  [in, optional] _Frees_ptr_opt_ BSTR bstrString
);
Parameters
[in, optional] bstrString

The previously allocated string. If this parameter is NULL, the function simply returns.

Return value
None

Requirements
*/

pub fn SysFreeString(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void SysFreeString(
    //   [in, optional] BSTR bstrString  // RCX
    // )
    
    let bstr_string = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[SysFreeString] bstrString: 0x{:x}", bstr_string);
    
    // Check for NULL pointer - function simply returns if NULL
    if bstr_string == 0 {
        log::info!("[SysFreeString] NULL BSTR pointer - returning without action");
        return Ok(());
    }
    
    // BSTR format:
    // [-4 bytes: length] [string data] [null terminator]
    // The BSTR pointer points to the string data, not the length prefix
    // So we need to free from (bstr_string - 4) to include the length prefix
    
    let allocation_start = bstr_string - 4;
    
    // Just free the memory - no need to read the content
    
    // Free the memory starting from the allocation address (including length prefix)
    {
        let mut heap = HEAP_ALLOCATIONS.lock().unwrap();
        match heap.free(allocation_start, emu) {
            Ok(_) => {
                log::info!("[SysFreeString] Successfully freed BSTR allocation at 0x{:x}", allocation_start);
            }
            Err(e) => {
                log::warn!("[SysFreeString] Failed to free BSTR allocation: {}", e);
                // Don't return error - SysFreeString should not fail even with invalid pointers
                // in some implementations, though it's undefined behavior
            }
        }
    }
    
    log::warn!("[SysFreeString] Mock implementation - freed BSTR at 0x{:x}", bstr_string);
    
    // SysFreeString returns void, no need to set RAX
    
    Ok(())
}