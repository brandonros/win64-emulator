/*
OleInitialize function (ole2.h)
10/12/2021
Initializes the COM library on the current apartment, identifies the concurrency model as single-thread apartment (STA), and enables additional functionality described in the Remarks section below. Applications must initialize the COM library before they can call COM library functions other than CoGetMalloc and memory allocation functions.

Syntax
C++

Copy
HRESULT OleInitialize(
  [in] LPVOID pvReserved
);
Parameters
[in] pvReserved

This parameter is reserved and must be NULL.

Return value
This function returns S_OK on success. Other possible values include the following.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use std::sync::atomic::{AtomicBool, Ordering};

// Track OLE initialization state
static OLE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Common HRESULT values
const S_OK: u32 = 0x00000000;
const S_FALSE: u32 = 0x00000001;
const RPC_E_CHANGED_MODE: u32 = 0x80010106;

pub fn OleInitialize(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HRESULT OleInitialize(
    //   LPVOID pvReserved  // RCX
    // )
    
    let reserved = emu.reg_read(RegisterX86::RCX)?;
    
    if reserved != 0 {
        log::warn!("[OleInitialize] pvReserved should be NULL, got: 0x{:x}", reserved);
    }
    
    // Check if already initialized
    let was_initialized = OLE_INITIALIZED.swap(true, Ordering::SeqCst);
    
    let result = if was_initialized {
        log::info!("[OleInitialize] OLE already initialized, returning S_FALSE");
        S_FALSE
    } else {
        log::info!("[OleInitialize] Successfully initialized OLE");
        S_OK
    };
    
    // Return HRESULT
    emu.reg_write(RegisterX86::RAX, result as u64)?;
    
    Ok(())
}