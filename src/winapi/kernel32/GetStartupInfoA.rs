use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetStartupInfoA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to STARTUPINFO structure from RCX register
    let startup_info_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[GetStartupInfoA] startup_info_ptr: 0x{:x}", startup_info_ptr);
    
    if startup_info_ptr > 0 {
        // Create a new StartupInfo64 structure with default values
        let startup_info = StartupInfo64::new();
        
        // Save the structure to the emulator memory at the provided address
        startup_info.save(emu, startup_info_ptr);
    }
    
    Ok(())
}