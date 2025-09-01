use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use crate::pe::MODULE_REGISTRY;
use crate::winapi;

pub fn GetModuleHandleA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let module_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    if module_name_ptr == 0 {
        // NULL module name means get handle to the current process
        match MODULE_REGISTRY.get_module_handle(None) {
            Some(handle) => {
                emu.reg_write(RegisterX86::RAX, handle)?;
                log::info!("kernel32!GetModuleHandleA(NULL) -> 0x{:016x}", handle);
            }
            None => {
                // This should rarely happen, but handle gracefully
                log::warn!("kernel32!GetModuleHandleA(NULL) - main module not found in registry");
                emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL on failure
                // Optionally set last error here if you have error handling
            }
        }
    } else {
        // Read the module name string from memory
        let module_name = memory::read_string_from_memory(emu, module_name_ptr)?;
        
        match MODULE_REGISTRY.get_module_handle(Some(&module_name)) {
            Some(handle) => {
                emu.reg_write(RegisterX86::RAX, handle)?;
                log::info!("kernel32!GetModuleHandleA('{}') -> 0x{:016x}", module_name, handle);
            }
            None => {
                // Module not found - return NULL as per Windows API specification
                log::warn!("kernel32!GetModuleHandleA('{}') - module not found in registry", module_name);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL on failure
                
                // If you have a SetLastError equivalent, you could set ERROR_MOD_NOT_FOUND (126) here
                winapi::set_last_error(emu, 126)?; // ERROR_MOD_NOT_FOUND
            }
        }
    }
    
    Ok(())
}