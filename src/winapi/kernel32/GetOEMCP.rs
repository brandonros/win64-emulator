use unicorn_engine::{Unicorn, RegisterX86};

pub fn GetOEMCP(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // UINT GetOEMCP(void) - no parameters
    // Returns the OEM code page identifier
    
    // 437 = OEM United States (DOS Latin US)
    // This is the traditional DOS code page for US systems
    let oem_code_page: u64 = 437;
    
    log::info!("[GetOEMCP] Returning OEM code page: {}", oem_code_page);
    
    // Set the return value in RAX register
    emu.reg_write(RegisterX86::RAX, oem_code_page)?;
    
    Ok(())
}