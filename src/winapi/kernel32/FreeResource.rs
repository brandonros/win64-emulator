use unicorn_engine::{Unicorn, RegisterX86};

pub fn FreeResource(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL FreeResource(
    //   HGLOBAL hResData  // RCX
    // )
    
    let h_res_data = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[FreeResource] hResData: 0x{:x}", h_res_data);
    
    // Check for NULL resource data handle
    if h_res_data == 0 {
        log::warn!("[FreeResource] NULL resource data handle");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // In modern Windows (Win32 and later), FreeResource is obsolete and does nothing
    // It always returns FALSE (0) and the system automatically frees resources
    // when the module is unloaded
    
    // The function exists only for backward compatibility with 16-bit Windows
    
    if h_res_data >= 0x1500000 && h_res_data < 0x1700000 {
        // This looks like one of our mock HGLOBAL handles from LoadResource
        log::info!("[FreeResource] Mock HGLOBAL handle detected: 0x{:x}", h_res_data);
        log::info!("[FreeResource] Note: FreeResource is obsolete in Win32 - no action taken");
    } else if h_res_data >= 0x500000 && h_res_data < 0x700000 {
        // This might be an HRSRC handle passed incorrectly
        log::warn!("[FreeResource] Warning: HRSRC handle passed instead of HGLOBAL");
    } else if h_res_data >= 0x2000000 && h_res_data < 0x3000000 {
        // This might be a locked resource pointer from LockResource
        log::warn!("[FreeResource] Warning: Locked resource pointer passed instead of HGLOBAL");
    } else {
        log::warn!("[FreeResource] Unknown handle format: 0x{:x}", h_res_data);
    }
    
    // According to Windows documentation:
    // "The return value is always FALSE"
    // "For resources loaded with LoadResource, the system automatically 
    //  deletes the resource when the process terminates"
    
    log::info!("[FreeResource] Returning FALSE (0) - resources are automatically freed");
    log::warn!("[FreeResource] This function is obsolete in Win32 and does nothing");
    
    emu.reg_write(RegisterX86::RAX, 0)?; // Always return FALSE
    
    Ok(())
}