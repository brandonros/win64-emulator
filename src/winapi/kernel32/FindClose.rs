use unicorn_engine::{Unicorn, RegisterX86};

pub fn FindClose(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let h_find_file = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[FindClose] Closing find handle: 0x{:x}, returning 1 (success)", h_find_file);
    
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}