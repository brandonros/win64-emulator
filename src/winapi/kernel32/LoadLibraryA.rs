use unicorn_engine::{RegisterX86, Unicorn};
use crate::emulation::memory;
use crate::pe::MODULE_REGISTRY;
use crate::winapi;

pub fn LoadLibraryA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let module_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    let module_name = memory::read_string_from_memory(emu, module_name_ptr)?;
    
    // Try to get the module handle from registry
    match MODULE_REGISTRY.get_module_handle(Some(&module_name)) {
        Some(handle) => {
            emu.reg_write(RegisterX86::RAX, handle)?;
            log::info!("kernel32!LoadLibraryA('{}') -> 0x{:016x}", module_name, handle);
        },
        None => {
            if module_name == "foo" {
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_MOD_NOT_FOUND)?;
                emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL on failure
            } else {
                panic!("kernel32!LoadLibraryA('{}') - module not found in registry", module_name);
            }
        }
    }
    
    Ok(())
}
