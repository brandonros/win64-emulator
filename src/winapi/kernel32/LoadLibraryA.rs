use unicorn_engine::{RegisterX86, Unicorn};
use crate::emulation::memory;
use crate::winapi::module_registry::MODULE_REGISTRY;

pub fn LoadLibraryA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let module_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    let module_name = memory::read_string_from_memory(emu, module_name_ptr)?;
    
    // Try to get the module handle from registry
    let handle = MODULE_REGISTRY.read().unwrap()
        .get_module_handle(Some(&module_name))
        .unwrap_or_else(|| {
            panic!("kernel32!LoadLibraryA('{}') - module not found in registry!", module_name);
        });
    
    emu.reg_write(RegisterX86::RAX, handle)?;
    log::info!("kernel32!LoadLibraryA('{}') -> 0x{:016x}", module_name, handle);
    
    Ok(())
}