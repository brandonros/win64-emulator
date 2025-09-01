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
*/

use unicorn_engine::Unicorn;

pub fn EnumDisplayMonitors(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    panic!("TODO");
}
