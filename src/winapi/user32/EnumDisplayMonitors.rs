use unicorn_engine::{Unicorn, RegisterX86};

// Primary monitor handle - same as in MonitorFromPoint
const PRIMARY_MONITOR_HANDLE: u64 = 0x10001;

pub fn EnumDisplayMonitors(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL EnumDisplayMonitors(
    //   [in] HDC             hdc,       // RCX
    //   [in] LPCRECT         lprcClip,  // RDX
    //   [in] MONITORENUMPROC lpfnEnum,  // R8
    //   [in] LPARAM          dwData     // R9
    // )
    
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
    
    // Read clipping rectangle if provided
    let _clip_rect = if lprc_clip != 0 {
        // RECT structure: left, top, right, bottom (4 x 32-bit integers)
        let mut rect_bytes = [0u8; 16];
        emu.mem_read(lprc_clip, &mut rect_bytes)?;
        
        let left = i32::from_le_bytes([rect_bytes[0], rect_bytes[1], rect_bytes[2], rect_bytes[3]]);
        let top = i32::from_le_bytes([rect_bytes[4], rect_bytes[5], rect_bytes[6], rect_bytes[7]]);
        let right = i32::from_le_bytes([rect_bytes[8], rect_bytes[9], rect_bytes[10], rect_bytes[11]]);
        let bottom = i32::from_le_bytes([rect_bytes[12], rect_bytes[13], rect_bytes[14], rect_bytes[15]]);
        
        log::info!("[EnumDisplayMonitors] Clipping rectangle: ({}, {}, {}, {})", left, top, right, bottom);
        Some((left, top, right, bottom))
    } else {
        log::info!("[EnumDisplayMonitors] No clipping rectangle");
        None
    };
    
    // Mock implementation: Simply return success without actually calling the callback
    // In a real scenario, the callback would be invoked for each monitor
    // For now, we'll just simulate that we enumerated one monitor successfully
    
    log::warn!("[EnumDisplayMonitors] Mock implementation - simulating enumeration of 1 monitor");
    log::info!("[EnumDisplayMonitors] Would call callback at 0x{:x} with monitor handle 0x{:x}", 
        lpfn_enum, PRIMARY_MONITOR_HANDLE);
    
    // Return TRUE for success (indicating successful enumeration)
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}
