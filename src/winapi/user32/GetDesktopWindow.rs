/*
GetDesktopWindow function (winuser.h)
02/22/2024
Retrieves a handle to the desktop window. The desktop window covers the entire screen. The desktop window is the area on top of which other windows are painted.

Syntax
C++

Copy
HWND GetDesktopWindow();
Return value
Type: HWND

The return value is a handle to the desktop window.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

// Mock desktop window handle - using a fixed value
const DESKTOP_WINDOW_HANDLE: u64 = 0x10010;

pub fn GetDesktopWindow(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HWND GetDesktopWindow()
    // No parameters
    
    log::info!("[GetDesktopWindow] Returning desktop window handle: 0x{:x}", DESKTOP_WINDOW_HANDLE);
    
    // Return the desktop window handle
    emu.reg_write(X86Register::RAX, DESKTOP_WINDOW_HANDLE)?;
    
    Ok(())
}