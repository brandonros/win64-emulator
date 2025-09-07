/*
GetDC function (winuser.h)
10/12/2021
The GetDC function retrieves a handle to a device context (DC) for the client area of a specified window or for the entire screen. You can use the returned handle in subsequent GDI functions to draw in the DC. The device context is an opaque data structure, whose values are used internally by GDI.

The GetDCEx function is an extension to GetDC, which gives an application more control over how and whether clipping occurs in the client area.

Syntax
C++

Copy
HDC GetDC(
  [in] HWND hWnd
);
Parameters
[in] hWnd

A handle to the window whose DC is to be retrieved. If this value is NULL, GetDC retrieves the DC for the entire screen.

Return value
If the function succeeds, the return value is a handle to the DC for the specified window's client area.

If the function fails, the return value is NULL.

Remarks
The GetDC function retrieves a common, class, or private DC depending on the class style of the specified window. For class and private DCs, GetDC leaves the previously assigned attributes unchanged. However, for common DCs, GetDC assigns default attributes to the DC each time it is retrieved. For example, the default font is System, which is a bitmap font. Because of this, the handle to a common DC returned by GetDC does not tell you what font, color, or brush was used when the window was drawn. To determine the font, call GetTextFace.

Note that the handle to the DC can only be used by a single thread at any one time.

After painting with a common DC, the ReleaseDC function must be called to release the DC. Class and private DCs do not have to be released. ReleaseDC must be called from the same thread that called GetDC. The number of DCs is limited only by available memory.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::atomic::{AtomicU64, Ordering};

// DC handle counter - starts at a non-zero value
static DC_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(0x20000);

pub fn GetDC(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HDC GetDC([in] HWND hWnd)
    // RCX = hWnd (handle to the window, or NULL for entire screen)
    
    let hwnd = emu.reg_read(X86Register::RCX)?;
    
    // Generate a new DC handle
    let hdc = DC_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    
    if hwnd == 0 {
        log::info!("[GetDC] Window handle: NULL (entire screen), returning DC handle: 0x{:x}", hdc);
    } else {
        log::info!("[GetDC] Window handle: 0x{:x}, returning DC handle: 0x{:x}", hwnd, hdc);
    }
    
    // Return the DC handle
    emu.reg_write(X86Register::RAX, hdc)?;
    
    Ok(())
}