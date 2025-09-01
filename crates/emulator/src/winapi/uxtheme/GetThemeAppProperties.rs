/*
GetThemeAppProperties function (uxtheme.h)
02/22/2024
Retrieves the property flags that control how visual styles are applied in the current application.

Syntax
C++

Copy
DWORD GetThemeAppProperties();
Return value
Type: DWORD

The following return values are bit flags combined with a logical OR operator.

Return code	Description
STAP_ALLOW_NONCLIENT
Specifies that the nonclient areas of application windows have visual styles applied.
STAP_ALLOW_CONTROLS
Specifies that controls in application windows have visual styles applied.
STAP_ALLOW_WEBCONTENT
Specifies that all web content displayed in an application is rendered using visual styles.
Remarks
Individual flags can be extracted from the result by combining the result with the logical AND of the desired flag.

Do not call this function during DllMain or global objects constructors. This may cause invalid return values.

Examples
The example extracts a single flag's state from the function result.

C++

Copy
DWORD resultFlags = GetThemeAppProperties();
bool ctrlsAreThemed = ((resultFlags & STAP_ALLOW_CONTROLS) != 0);
*/

use unicorn_engine::{Unicorn, RegisterX86};

// Theme app property flags
const STAP_ALLOW_NONCLIENT: u32 = 0x00000001;
const STAP_ALLOW_CONTROLS: u32 = 0x00000002;
const STAP_ALLOW_WEBCONTENT: u32 = 0x00000004;

pub fn GetThemeAppProperties(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetThemeAppProperties()
    // No parameters
    
    log::info!("[GetThemeAppProperties] Called");
    
    // Return all flags enabled (typical for modern Windows applications)
    let properties = STAP_ALLOW_NONCLIENT | STAP_ALLOW_CONTROLS | STAP_ALLOW_WEBCONTENT;
    
    emu.reg_write(RegisterX86::RAX, properties as u64)?;
    
    log::info!("[GetThemeAppProperties] Returning 0x{:x} (NONCLIENT | CONTROLS | WEBCONTENT)", properties);
    
    Ok(())
}