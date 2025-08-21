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
    
    let proc_address = match registry.get_loaded_module_by_module_base(module_base) {
        Some(loaded_module) => {
            match loaded_module.get_proc_address(&proc_name) {
                Some(address) => {
                    log::info!("kernel32!GetProcAddress(0x{:016x}, '{}') -> 0x{:016x}", 
                              module_base, proc_name, address);
                    address
                }
                None => {
                    log::warn!("kernel32!GetProcAddress(0x{:016x}, '{}') - function not found in module exports!", 
                              module_base, proc_name);
                    0  // Return NULL on failure
                }
            }
        }
        None => {
            log::warn!("kernel32!GetProcAddress(0x{:016x}, '{}') - module not found!", 
                      module_base, proc_name);
            0  // Return NULL on failure
        }
    };
    
    // Return the address in RAX
    emu.reg_write(RegisterX86::RAX, proc_address)?;
    
    Ok(())
}