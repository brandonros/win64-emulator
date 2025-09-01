/*
SetThreadDescription function (processthreadsapi.h)
02/22/2024
Assigns a description to a thread.

Syntax
C++

Copy
HRESULT SetThreadDescription(
  [in] HANDLE hThread,
  [in] PCWSTR lpThreadDescription
);
Parameters
[in] hThread

A handle for the thread for which you want to set the description. The handle must have THREAD_SET_LIMITED_INFORMATION access.

[in] lpThreadDescription

A Unicode string that specifies the description of the thread.

Return value
If the function succeeds, the return value is the HRESULT that denotes a successful operation. If the function fails, the return value is an HRESULT that denotes the error.
*/

use unicorn_engine::{Unicorn, RegisterX86};

pub fn SetThreadDescription(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HRESULT SetThreadDescription(
    //   [in] HANDLE hThread,              // RCX
    //   [in] PCWSTR lpThreadDescription   // RDX
    // );
    
    let h_thread = emu.reg_read(RegisterX86::RCX)?;
    let description_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    log::info!("[SetThreadDescription] hThread: 0x{:x}, lpThreadDescription: 0x{:x}", 
              h_thread, description_ptr);
    
    // Mock implementation - just return success (S_OK = 0)
    emu.reg_write(RegisterX86::RAX, 0)?;
    
    log::info!("[SetThreadDescription] Returning S_OK");
    
    Ok(())
}