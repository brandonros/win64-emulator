/*
AddVectoredExceptionHandler function (errhandlingapi.h)
04/01/2021
Registers a vectored exception handler.

Syntax
C++

Copy
PVOID AddVectoredExceptionHandler(
  ULONG                       First,
  PVECTORED_EXCEPTION_HANDLER Handler
);
Parameters
First

The order in which the handler should be called. If the parameter is nonzero, the handler is the first handler to be called. If the parameter is zero, the handler is the last handler to be called.

Handler

A pointer to the handler to be called. For more information, see VectoredHandler.

Return value
If the function succeeds, the return value is a handle to the exception handler.

If the function fails, the return value is NULL.

Remarks
If the First parameter is nonzero, the handler is the first handler to be called until a subsequent call to AddVectoredExceptionHandler is used to specify a different handler as the first handler.

If the VectoredHandler parameter points to a function in a DLL and that DLL is unloaded, the handler is still registered. This can lead to application errors.

To unregister the handler, use the RemoveVectoredExceptionHandler function function.

To compile an application that uses this function, define the _WIN32_WINNT macro as 0x0500 or later. For more information, see Using the Windows Headers.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashSet;
use std::sync::{LazyLock, RwLock};

// Simple counter for generating unique handler handles
static HANDLER_COUNTER: AtomicU64 = AtomicU64::new(0x1000);

// Shared tracking of registered exception handler handles
pub static REGISTERED_HANDLERS: LazyLock<RwLock<HashSet<u64>>> = LazyLock::new(|| {
    RwLock::new(HashSet::new())
});

pub fn AddVectoredExceptionHandler(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // PVOID AddVectoredExceptionHandler(
    //   ULONG First,                        // RCX
    //   PVECTORED_EXCEPTION_HANDLER Handler  // RDX
    // );
    
    let first = emu.reg_read(X86Register::RCX)?;
    let handler = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[AddVectoredExceptionHandler] First: {}, Handler: 0x{:x}", first, handler);
    
    // Mock implementation - just return a fake handle
    // In a real implementation, we would:
    // 1. Store the handler in a list
    // 2. Respect the First parameter for ordering
    // 3. Actually call the handler on exceptions
    
    if handler == 0 {
        log::warn!("[AddVectoredExceptionHandler] NULL handler provided, returning NULL");
        emu.reg_write(X86Register::RAX, 0)?;
    } else {
        // Generate a unique handle for this handler
        let handle = HANDLER_COUNTER.fetch_add(1, Ordering::SeqCst);
        
        // Add the handle to the shared tracking set
        {
            let mut handlers = REGISTERED_HANDLERS.write().unwrap();
            handlers.insert(handle);
        }
        
        log::info!("[AddVectoredExceptionHandler] Registered handler 0x{:x} with handle 0x{:x}", 
                  handler, handle);
        emu.reg_write(X86Register::RAX, handle)?;
    }
    
    Ok(())
}