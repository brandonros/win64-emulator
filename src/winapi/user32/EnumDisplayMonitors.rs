/*
EnumDisplayMonitors function (winuser.h)
10/12/2021
The EnumDisplayMonitors function enumerates display monitors (including invisible pseudo-monitors associated with the mirroring drivers) that intersect a region formed by the intersection of a specified clipping rectangle and the visible region of a device context. EnumDisplayMonitors calls an application-defined MonitorEnumProc callback function once for each monitor that is enumerated. Note that GetSystemMetrics (SM_CMONITORS) counts only the display monitors.

Syntax
C++

Copy
BOOL EnumDisplayMonitors(
  [in] HDC             hdc,
  [in] LPCRECT         lprcClip,
  [in] MONITORENUMPROC lpfnEnum,
  [in] LPARAM          dwData
);
Parameters
[in] hdc

A handle to a display device context that defines the visible region of interest.

If this parameter is NULL, the hdcMonitor parameter passed to the callback function will be NULL, and the visible region of interest is the virtual screen that encompasses all the displays on the desktop.

[in] lprcClip

A pointer to a RECT structure that specifies a clipping rectangle. The region of interest is the intersection of the clipping rectangle with the visible region specified by hdc.

If hdc is non-NULL, the coordinates of the clipping rectangle are relative to the origin of the hdc. If hdc is NULL, the coordinates are virtual-screen coordinates.

This parameter can be NULL if you don't want to clip the region specified by hdc.

[in] lpfnEnum

A pointer to a MonitorEnumProc application-defined callback function.

[in] dwData

Application-defined data that EnumDisplayMonitors passes directly to the MonitorEnumProc function.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero.

Remarks
There are two reasons to call the EnumDisplayMonitors function:

You want to draw optimally into a device context that spans several display monitors, and the monitors have different color formats.
You want to obtain a handle and position rectangle for one or more display monitors.
To determine whether all the display monitors in a system share the same color format, call GetSystemMetrics (SM_SAMEDISPLAYFORMAT).
You do not need to use the EnumDisplayMonitors function when a window spans display monitors that have different color formats. You can continue to paint under the assumption that the entire screen has the color properties of the primary monitor. Your windows will look fine. EnumDisplayMonitors just lets you make them look better.

Setting the hdc parameter to NULL lets you use the EnumDisplayMonitors function to obtain a handle and position rectangle for one or more display monitors. The following table shows how the four combinations of NULL and non-NULLhdc and lprcClip values affect the behavior of the EnumDisplayMonitors function.

hdc	lprcRect	EnumDisplayMonitors behavior
NULL	NULL	Enumerates all display monitors.The callback function receives a NULL HDC.
NULL	non-NULL	Enumerates all display monitors that intersect the clipping rectangle. Use virtual screen coordinates for the clipping rectangle.The callback function receives a NULL HDC.
non-NULL	NULL	Enumerates all display monitors that intersect the visible region of the device context.The callback function receives a handle to a DC for the specific display monitor.
non-NULL	non-NULL	Enumerates all display monitors that intersect the visible region of the device context and the clipping rectangle. Use device context coordinates for the clipping rectangle.The callback function receives a handle to a DC for the specific display monitor.
 
Examples
To paint in response to a WM_PAINT message, using the capabilities of each monitor, you can use code like this in a window procedure:


Copy

case WM_PAINT:
  hdc = BeginPaint(hwnd, &ps);
  EnumDisplayMonitors(hdc, NULL, MyPaintEnumProc, 0);
  EndPaint(hwnd, &ps);

To paint the top half of a window using the capabilities of each monitor, you can use code like this:


Copy

GetClientRect(hwnd, &rc);
rc.bottom = (rc.bottom - rc.top) / 2;
hdc = GetDC(hwnd);
EnumDisplayMonitors(hdc, &rc, MyPaintEnumProc, 0);
ReleaseDC(hwnd, hdc);

To paint the entire virtual screen optimally for each display monitor, you can use code like this:


Copy

hdc = GetDC(NULL);
EnumDisplayMonitors(hdc, NULL, MyPaintScreenEnumProc, 0);
ReleaseDC(NULL, hdc);

To retrieve information about all of the display monitors, use code like this:


Copy

EnumDisplayMonitors(NULL, NULL, MyInfoEnumProc, 0);  
*/

use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::Foundation::RECT;

use crate::emulation::memory::{self, heap_manager::HEAP_ALLOCATIONS};

// Primary monitor handle - same as in MonitorFromPoint
const PRIMARY_MONITOR_HANDLE: u64 = 0x10001;

pub fn EnumDisplayMonitors(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let hdc = emu.reg_read(RegisterX86::RCX)?;
    let lprc_clip = emu.reg_read(RegisterX86::RDX)?;
    let lpfn_enum = emu.reg_read(RegisterX86::R8)?;
    let dw_data = emu.reg_read(RegisterX86::R9)?;
    
    log::info!("[EnumDisplayMonitors] HDC: 0x{:x}, lprcClip: 0x{:x}, lpfnEnum: 0x{:x}, dwData: 0x{:x}",
        hdc, lprc_clip, lpfn_enum, dw_data);
    
    // Check for NULL callback
    if lpfn_enum == 0 {
        log::error!("[EnumDisplayMonitors] NULL callback function");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Allocate memory for the RECT structure using heap manager
    let rect_addr = {
        let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
        match heap_mgr.allocate(emu, std::mem::size_of::<RECT>()) {
            Ok(addr) => {
                log::info!("[EnumDisplayMonitors] Allocated RECT at 0x{:x}", addr);
                addr
            }
            Err(e) => {
                log::error!("[EnumDisplayMonitors] Failed to allocate RECT: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
                return Ok(());
            }
        }
    };
    
    // Create RECT for the primary monitor
    let monitor_rect = RECT {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    };
    
    // Write the RECT struct to memory
    memory::write_struct(emu, rect_addr, &monitor_rect)?;
    
    // Save current context
    let old_rsp = emu.reg_read(RegisterX86::RSP)?;
    let old_rip = emu.reg_read(RegisterX86::RIP)?;
    
    // Allocate memory for return stub using heap manager
    let return_addr = {
        let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
        match heap_mgr.allocate(emu, 16) { // Small allocation for RET instruction
            Ok(addr) => {
                log::info!("[EnumDisplayMonitors] Allocated return stub at 0x{:x}", addr);
                addr
            }
            Err(e) => {
                // Clean up the RECT allocation before returning
                heap_mgr.free(rect_addr, emu).ok();
                log::error!("[EnumDisplayMonitors] Failed to allocate return stub: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    };

    // Write a RET instruction at the return address
    emu.mem_write(return_addr, &[0xC3])?; // x64 RET opcode
    
    // Prepare stack for callback call
    let new_rsp = (old_rsp - 0x40) & !0xF; // Extra space + alignment
    emu.reg_write(RegisterX86::RSP, new_rsp)?;
    
    // Push return address on stack
    emu.mem_write(new_rsp, &return_addr.to_le_bytes())?;
    
    // Set up parameters for callback:
    // BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
    emu.reg_write(RegisterX86::RCX, PRIMARY_MONITOR_HANDLE)?;  // hMonitor
    emu.reg_write(RegisterX86::RDX, if hdc != 0 { hdc } else { 0 })?; // hdcMonitor
    emu.reg_write(RegisterX86::R8, rect_addr)?;  // lprcMonitor
    emu.reg_write(RegisterX86::R9, dw_data)?;    // dwData (pass through)
    
    // Set RIP to callback function
    emu.reg_write(RegisterX86::RIP, lpfn_enum)?;
    
    log::info!("[EnumDisplayMonitors] Executing callback at 0x{:x} for monitor rect ({},{},{},{})", 
        lpfn_enum, monitor_rect.left, monitor_rect.top, monitor_rect.right, monitor_rect.bottom);
    
    // Execute until we hit the return address
    let result = emu.emu_start(lpfn_enum, return_addr, 0, 0);
    
    let callback_succeeded = match result {
        Ok(_) => {
            // Get the callback's return value (BOOL in RAX)
            let callback_result = emu.reg_read(RegisterX86::RAX)?;
            log::info!("[EnumDisplayMonitors] Callback returned: {}", callback_result);
            
            // If callback returned FALSE (0), enumeration should stop
            if callback_result == 0 {
                log::info!("[EnumDisplayMonitors] Callback requested to stop enumeration");
            }
            true
        }
        Err(e) => {
            log::error!("[EnumDisplayMonitors] Error executing callback: {:?}", e);
            false
        }
    };
    
    // Free the allocated RECT memory
    {
        let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
        if let Err(e) = heap_mgr.free(rect_addr, emu) {
            log::warn!("[EnumDisplayMonitors] Failed to free RECT at 0x{:x}: {}", rect_addr, e);
        } else {
            log::info!("[EnumDisplayMonitors] Freed RECT at 0x{:x}", rect_addr);
        }
    }
    
    // Restore original context
    emu.reg_write(RegisterX86::RSP, old_rsp)?;
    emu.reg_write(RegisterX86::RIP, old_rip)?;
    
    // Return based on callback success
    emu.reg_write(RegisterX86::RAX, if callback_succeeded { 1 } else { 0 })?;
    
    Ok(())
}
