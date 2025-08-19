use unicorn_engine::{RegisterX86, Unicorn};
use crate::emulation::memory;
use crate::winapi::module_registry::MODULE_REGISTRY;

pub fn GetProcAddress(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    // RCX = module handle (base address)
    // RDX = function name pointer
    
    let module_base = emu.reg_read(RegisterX86::RCX)?;
    let proc_name_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    // Read the function name from memory
    let proc_name = memory::read_string_from_memory(emu, proc_name_ptr)?;
    
    // Look up the function in the module's exports
    let registry = MODULE_REGISTRY.read().unwrap();
    let proc_address = registry.get_proc_address(module_base, &proc_name)
        .unwrap_or_else(|| {
            log::warn!("kernel32!GetProcAddress(0x{:016x}, '{}') - function not found!", 
                      module_base, proc_name);
            0  // Return NULL on failure
        });
    
    // Return the mock address in RAX
    emu.reg_write(RegisterX86::RAX, proc_address)?;
    
    log::info!("kernel32!GetProcAddress(0x{:016x}, '{}') -> 0x{:016x}", 
              module_base, proc_name, proc_address);
    
    Ok(())
}