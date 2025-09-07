use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use crate::winapi;
use crate::pe::MODULE_REGISTRY;

pub fn GetProcAddress(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    // RCX = module handle (base address)
    // RDX = function name pointer
    
    let module_base = emu.reg_read(X86Register::RCX)?;
    let proc_name_ptr = emu.reg_read(X86Register::RDX)?;
    
    // Read the function name from memory
    let proc_name = memory::read_string_from_memory(emu, proc_name_ptr)?;
    
    // Look up the function in the module's exports
    match MODULE_REGISTRY.get_loaded_module_by_module_base(module_base) {
        Some(loaded_module) => {
            let module_name = &loaded_module.name;
            match loaded_module.get_proc_address(&proc_name) {
                Some(address) => {
                    log::info!("kernel32!GetProcAddress({} @ 0x{:016x}, '{}') -> 0x{:016x}", 
                              module_name, module_base, proc_name, address);
                    emu.reg_write(X86Register::RAX, address)?;
                }
                None => {
                    log::warn!("kernel32!GetProcAddress({} @ 0x{:016x}, '{}') - function not found!", 
                              module_name, module_base, proc_name);
                    winapi::set_last_error(emu, 127)?; // ERROR_PROC_NOT_FOUND
                    emu.reg_write(X86Register::RAX, 0)?;
                }
            }
        }
        None => {
            log::warn!("kernel32!GetProcAddress(0x{:016x}, '{}') - module not found!", 
                      module_base, proc_name);
            winapi::set_last_error(emu, 126)?; // ERROR_MOD_NOT_FOUND
            emu.reg_write(X86Register::RAX, 0)?;
        }
    }
    
    Ok(())
}
