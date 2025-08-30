use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use std::sync::OnceLock;

use crate::emulation::memory;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

// Store the command line address once allocated
static COMMAND_LINE_A_ADDRESS: OnceLock<u64> = OnceLock::new();

pub fn GetCommandLineA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Check if already initialized
    let cmd_addr = if let Some(&addr) = COMMAND_LINE_A_ADDRESS.get() {
        addr
    } else {
        // First call - allocate and initialize
        let command_line = "C:\\Windows\\System32\\main.exe";
        
        // Calculate size needed (including null terminator)
        let size = command_line.len() + 1;
        
        // Allocate from heap
        let addr = HEAP_ALLOCATIONS.lock().unwrap()
            .allocate(size)
            .map_err(|e| {
                log::error!("[GetCommandLineA] {}", e);
                unicorn_engine::uc_error::NOMEM
            })?;
        
        // Write the string to memory
        memory::write_string_to_memory(emu, addr, command_line)?;
        
        log::info!("[GetCommandLineA] Initialized command line at 0x{:x}: \"{}\"", 
                  addr, command_line);
        
        // Store for future calls
        COMMAND_LINE_A_ADDRESS.set(addr).expect("Failed to set command line address");
        
        addr
    };
    
    log::debug!("[GetCommandLineA] Returning command line pointer: 0x{:x}", cmd_addr);
    
    // Return pointer in RAX
    emu.reg_write(RegisterX86::RAX, cmd_addr)?;
    
    Ok(())
}