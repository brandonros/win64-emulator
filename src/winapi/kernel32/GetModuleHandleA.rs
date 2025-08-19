use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::read_string_from_memory;
use crate::winapi::module_registry::MODULE_REGISTRY;

pub fn GetModuleHandleA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let module_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    if module_name_ptr == 0 {
        // NULL module name means get handle to the current process
        let handle = MODULE_REGISTRY.read().unwrap()
            .get_module_handle(None)
            .expect("Main module should always be registered");
        emu.reg_write(RegisterX86::RAX, handle)?;
        log::info!("kernel32!GetModuleHandleA(NULL) -> 0x{:016x}", handle);
    } else {
        // Read the module name string from memory
        let module_name = read_string_from_memory(emu, module_name_ptr)?;
        let handle = MODULE_REGISTRY.read().unwrap()
            .get_module_handle(Some(&module_name))
            .unwrap_or_else(|| {
                panic!("kernel32!GetModuleHandleA('{}') - module not found in registry!", module_name);
            });
        emu.reg_write(RegisterX86::RAX, handle)?;
        log::info!("kernel32!GetModuleHandleA('{}') -> 0x{:016x}", module_name, handle);
    }
    
    Ok(())
}