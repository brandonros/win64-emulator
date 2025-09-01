/*
char*** CDECL MSVCRT___p___argv(void) { return &MSVCRT___argv; }
*/

use unicorn_engine::{Unicorn, RegisterX86};
use std::sync::OnceLock;
use crate::emulation::memory;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

// Store the argv pointer address once allocated
static ARGV_POINTER_ADDRESS: OnceLock<u64> = OnceLock::new();

pub fn __p___argv(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Check if already initialized
    let p_argv_addr = if let Some(&addr) = ARGV_POINTER_ADDRESS.get() {
        addr
    } else {
        // First call - allocate and initialize
        let prog_name = "C:\\Windows\\System32\\program.exe";
        
        // Allocate space for program name string
        let prog_name_size = prog_name.len() + 1;
        let prog_name_addr = HEAP_ALLOCATIONS.lock().unwrap()
            .allocate(emu, prog_name_size)
            .map_err(|e| {
                log::error!("[__p___argv] Failed to allocate program name: {}", e);
                unicorn_engine::uc_error::NOMEM
            })?;
        
        // Write program name string
        memory::write_string_to_memory(emu, prog_name_addr, prog_name)?;
        
        // Allocate space for argv array (2 pointers: program name and null)
        let argv_array_addr = HEAP_ALLOCATIONS.lock().unwrap()
            .allocate(emu, 16) // 2 * sizeof(pointer) on x64
            .map_err(|e| {
                log::error!("[__p___argv] Failed to allocate argv array: {}", e);
                unicorn_engine::uc_error::NOMEM
            })?;
        
        // Write argv array
        emu.mem_write(argv_array_addr, &prog_name_addr.to_le_bytes())?; // argv[0]
        emu.mem_write(argv_array_addr + 8, &0u64.to_le_bytes())?; // argv[1] = NULL
        
        // Allocate space for pointer to argv array
        let p_argv_addr = HEAP_ALLOCATIONS.lock().unwrap()
            .allocate(emu, 8) // sizeof(pointer) on x64
            .map_err(|e| {
                log::error!("[__p___argv] Failed to allocate p_argv: {}", e);
                unicorn_engine::uc_error::NOMEM
            })?;
        
        // Write pointer to argv array
        emu.mem_write(p_argv_addr, &argv_array_addr.to_le_bytes())?;
        
        log::info!("[__p___argv] Initialized argv at 0x{:x} -> 0x{:x} -> \"{}\"", 
                  p_argv_addr, argv_array_addr, prog_name);
        
        // Store for future calls
        ARGV_POINTER_ADDRESS.set(p_argv_addr).expect("Failed to set argv pointer address");
        
        p_argv_addr
    };
    
    log::debug!("[__p___argv] Returning argv pointer pointer: 0x{:x}", p_argv_addr);
    
    // Return pointer in RAX
    emu.reg_write(RegisterX86::RAX, p_argv_addr)?;
    
    Ok(())
}