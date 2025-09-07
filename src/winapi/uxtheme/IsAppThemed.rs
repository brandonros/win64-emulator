/*
IsAppThemed function (uxtheme.h)
02/22/2024
Reports whether the current application's user interface displays using visual styles.

Syntax
C++

Copy
BOOL IsAppThemed();
Return value
Type: BOOL

Returns one of the following values.

Return code	Description
TRUE
The application has a visual style applied.
FALSE
The application does not have a visual style applied.
Remarks
Prior to Windows 8, a visual style can be turned off in Control Panel, so that an application can support visual styles but not have a visual style applied at a given time.

In Windows 8, it is not possible to turn off visual styles.

Do not call this function during DllMain or global objects constructors. This may cause invalid return values.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn IsAppThemed(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL IsAppThemed()
    // No parameters
    
    log::info!("[IsAppThemed] Called");
    
    // Return TRUE to indicate the application is themed
    // In Windows 8+, visual styles cannot be turned off
    emu.reg_write(X86Register::RAX, 1)?; // TRUE
    
    log::info!("[IsAppThemed] Returning TRUE (app is themed)");
    
    Ok(())
}