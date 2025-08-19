use unicorn_engine::{Unicorn, RegisterX86};

pub fn GetModuleHandleA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let module_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    if module_name_ptr == 0 {
        // NULL module name means get handle to the current process
        // For now, return the base address of the loaded PE (0x140000000)
        emu.reg_write(RegisterX86::RAX, 0x140000000)?;
        log::info!("kernel32!GetModuleHandleA(NULL) -> 0x140000000");
    } else {
        // Read the module name string from memory
        let module_name = read_string_from_memory(emu, module_name_ptr)?;
        
        // For simplicity, we'll just return a fixed address for known modules
        // In a real implementation, you'd look up the actual loaded module
        let handle = match module_name.to_lowercase().as_str() {
            "kernel32.dll" | "kernel32" => 0x7FF800000000,
            "ntdll.dll" | "ntdll" => 0x7FF900000000,
            _ => panic!("kernel32!GetModuleHandleA('{}') -> NULL (module not found)", module_name),
        };
        
        emu.reg_write(RegisterX86::RAX, handle)?;
        log::info!("kernel32!GetModuleHandleA('{}') -> 0x{:016x}", module_name, handle);
    }
    
    Ok(())
}

fn read_string_from_memory(emu: &mut Unicorn<()>, addr: u64) -> Result<String, unicorn_engine::uc_error> {
    let mut bytes = Vec::new();
    let mut current_addr = addr;
    
    // Read up to 256 bytes or until we hit a null terminator
    for _ in 0..256 {
        let mut byte = [0u8; 1];
        emu.mem_read(current_addr, &mut byte)?;
        
        if byte[0] == 0 {
            break;
        }
        
        bytes.push(byte[0]);
        current_addr += 1;
    }
    
    Ok(String::from_utf8_lossy(&bytes).to_string())
}