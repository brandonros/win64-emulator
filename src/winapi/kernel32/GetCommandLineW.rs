use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use std::sync::OnceLock;

use crate::emulation::memory;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

// Store the command line address once allocated
static COMMAND_LINE_W_ADDRESS: OnceLock<u64> = OnceLock::new();

pub fn GetCommandLineW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Check if already initialized
    let cmd_addr = if let Some(&addr) = COMMAND_LINE_W_ADDRESS.get() {
        addr
    } else {
        // First call - allocate and initialize
        let command_line = "C:\\Windows\\System32\\emulated.exe";
        
        // Convert to UTF-16 wide string
        let wide_chars: Vec<u16> = command_line.encode_utf16().collect();
        
        // Calculate size needed in bytes (wide chars + null terminator)
        let size = (wide_chars.len() + 1) * 2; // 2 bytes per wide char
        
        // Allocate from heap
        let addr = HEAP_ALLOCATIONS.lock().unwrap()
            .allocate(size)
            .map_err(|e| {
                log::error!("[GetCommandLineW] {}", e);
                unicorn_engine::uc_error::NOMEM
            })?;
        
        // Write the wide string to memory
        memory::write_wide_string_to_memory(emu, addr, command_line)?;
        
        log::info!("[GetCommandLineW] Initialized command line at 0x{:x}: \"{}\"", 
                  addr, command_line);
        
        // Store for future calls
        COMMAND_LINE_W_ADDRESS.set(addr).expect("Failed to set command line address");
        
        addr
    };
    
    log::debug!("[GetCommandLineW] Returning command line pointer: 0x{:x}", cmd_addr);
    
    // Return pointer in RAX
    emu.reg_write(RegisterX86::RAX, cmd_addr)?;
    
    Ok(())
}