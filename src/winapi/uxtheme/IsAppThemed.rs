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

use unicorn_engine::{Unicorn, RegisterX86};

pub fn IsAppThemed(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL IsAppThemed()
    // No parameters
    
    log::info!("[IsAppThemed] Called");
    
    // Return TRUE to indicate the application is themed
    // In Windows 8+, visual styles cannot be turned off
    emu.reg_write(RegisterX86::RAX, 1)?; // TRUE
    
    log::info!("[IsAppThemed] Returning TRUE (app is themed)");
    
    Ok(())
}