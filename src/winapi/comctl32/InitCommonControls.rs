/*
InitCommonControls function (commctrl.h)
02/22/2024
Registers and initializes certain common control window classes. This function is obsolete. New applications should use the InitCommonControlsEx function.

Syntax
C++

Copy
void InitCommonControls();
Return value
None
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError};

pub fn InitCommonControls(_emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // void InitCommonControls()
    // No parameters, no return value
    
    log::info!("[InitCommonControls] Initializing common controls (no-op)");
    
    // This function doesn't return anything and just ensures 
    // comctl32.dll is loaded. In our emulator, it's a no-op.
    
    Ok(())
}