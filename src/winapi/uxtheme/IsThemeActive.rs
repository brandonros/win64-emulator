/*
IsThemeActive function (uxtheme.h)
02/22/2024
Tests if a visual style for the current application is active.

Syntax
C++

Copy
BOOL IsThemeActive();
Return value
Type: BOOL

Returns one of the following values.

Return code	Description
TRUE
A visual style is enabled, and windows with visual styles applied should call OpenThemeData to start using theme drawing services.
FALSE
A visual style is not enabled, and the window message handler does not need to make another call to IsThemeActive until it receives a WM_THEMECHANGED message.
Remarks
Do not call this function during DllMain or global objects constructors. This may cause invalid return values.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn IsThemeActive(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL IsThemeActive()
    // No parameters
    
    log::info!("[IsThemeActive] Called");
    
    // Return TRUE to indicate visual styles are enabled
    // Modern Windows has visual styles always active
    emu.reg_write(X86Register::RAX, 1)?; // TRUE
    
    log::info!("[IsThemeActive] Returning TRUE (visual styles are active)");
    
    Ok(())
}