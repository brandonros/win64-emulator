use unicorn_engine::{RegisterX86, Unicorn};
use crate::pe::MODULE_REGISTRY;
use crate::winapi;

pub fn FreeLibrary(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL FreeLibrary(
    //   HMODULE hLibModule
    // )
    
    let h_lib_module = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("kernel32!FreeLibrary(0x{:016x})", h_lib_module);
    
    // Check for NULL handle
    if h_lib_module == 0 {
        log::warn!("kernel32!FreeLibrary - NULL handle provided ERROR_INVALID_HANDLE");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Check if the module handle exists in registry
    let module_exists = MODULE_REGISTRY
        .get_module_by_handle(h_lib_module)
        .is_some();
    
    if module_exists {
        // In a real implementation, you might decrease reference count here
        // For simulation, we just succeed
        log::info!("kernel32!FreeLibrary(0x{:016x}) -> TRUE (success)", h_lib_module);
        emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE
    } else {
        log::warn!("kernel32!FreeLibrary(0x{:016x}) - invalid module handle ERROR_INVALID_HANDLE", h_lib_module);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
    }
    
    Ok(())
}