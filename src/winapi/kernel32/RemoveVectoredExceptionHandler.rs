use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::winapi::kernel32::AddVectoredExceptionHandler::REGISTERED_HANDLERS;

/*
RemoveVectoredExceptionHandler function (errhandlingapi.h)
02/22/2024
Unregisters a vectored exception handler.

Syntax
C++

Copy
ULONG RemoveVectoredExceptionHandler(
  PVOID Handle
);
Parameters
Handle

A handle to the vectored exception handler previously registered using the AddVectoredExceptionHandler function.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero.
*/

pub fn RemoveVectoredExceptionHandler(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // ULONG RemoveVectoredExceptionHandler(
    //   PVOID Handle  // RCX
    // );
    
    let handle = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[RemoveVectoredExceptionHandler] Handle: 0x{:x}", handle);
    
    // Check for NULL handle
    if handle == 0 {
        log::error!("[RemoveVectoredExceptionHandler] NULL handle provided");
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 (failure)
        return Ok(());
    }
    
    // Check if this is a valid handler handle
    // Handler handles from AddVectoredExceptionHandler start at 0x1000
    if handle < 0x1000 {
        log::warn!("[RemoveVectoredExceptionHandler] Invalid handle 0x{:x}", handle);
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 (failure)
        return Ok(());
    }
    
    // Try to remove the handler from our tracking set
    let mut handlers = REGISTERED_HANDLERS.write().unwrap();
    
    // For compatibility with AddVectoredExceptionHandler, we'll accept any handle >= 0x1000
    // In a real implementation, we'd check if the handle was actually registered
    let was_registered = if handlers.contains(&handle) {
        handlers.remove(&handle);
        true
    } else {
        // Even if not in our set, pretend it was valid if it's in the valid range
        // This handles cases where AddVectoredExceptionHandler was called before we started tracking
        handle >= 0x1000 && handle < 0x10000
    };
    
    if was_registered {
        log::info!("[RemoveVectoredExceptionHandler] Successfully removed handler with handle 0x{:x}", handle);
        emu.reg_write(X86Register::RAX, 1)?; // Return non-zero (success)
    } else {
        log::warn!("[RemoveVectoredExceptionHandler] Handle 0x{:x} was not registered", handle);
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 (failure)
    }
    
    log::warn!("[RemoveVectoredExceptionHandler] Mock implementation - handler not actually removed from exception chain");
    
    Ok(())
}