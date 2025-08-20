use unicorn_engine::{uc_error, Permission, Unicorn};
use crate::pe::LoadedPE;

pub mod constants;
pub mod utils;
pub mod teb;
pub mod peb;

// Re-export commonly used items
pub use constants::*;
pub use utils::{read_string_from_memory, read_wide_string_from_memory};
pub use utils::{write_word_le, write_word_be, write_dword_le, write_dword_be, write_qword_le, write_qword_be};
pub use teb::setup_teb;
pub use peb::setup_peb;

pub fn setup_memory(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n🗺️  Setting up memory layout:");
    
    // For packed executables, we need to ensure the entry point is covered
    let entry_point = pe.entry_point();
    
    // Calculate total memory needed, including entry point
    let mut min_addr = entry_point.min(pe.image_base());
    let mut max_addr = entry_point.max(pe.image_base());
    
    for section in pe.sections() {
        min_addr = min_addr.min(section.virtual_address());
        max_addr = max_addr.max(section.virtual_address() + section.virtual_size());
    }
    
    // Ensure entry point is covered
    min_addr = min_addr.min(entry_point);
    max_addr = max_addr.max(entry_point + 0x1000); // Give some space around entry point
    
    // Align to page boundaries
    let page_size = 0x1000;
    min_addr = min_addr & !(page_size - 1);
    max_addr = (max_addr + page_size - 1) & !(page_size - 1);
    
    let total_size = max_addr - min_addr;
    
    log::info!("  Image range: 0x{:016x} - 0x{:016x} (size: 0x{:x})", 
             min_addr, max_addr, total_size);
    log::info!("  Entry point: 0x{:016x} (covered: {})", 
             entry_point, entry_point >= min_addr && entry_point < max_addr);
    
    // Map the entire image range
    emu.mem_map(min_addr, total_size as usize, Permission::READ | Permission::WRITE | Permission::EXEC)?;
    
    // Load section data
    for section in pe.sections() {
        if !section.raw_data().is_empty() {
            emu.mem_write(section.virtual_address(), &section.raw_data())?;
            log::info!("  Loaded section '{}' at 0x{:016x}", 
                     section.name(), section.virtual_address());
        }
    }
    
    // Check if entry point has code - if not, this might be a packed executable
    let mut entry_code = vec![0u8; 16];
    if let Ok(()) = emu.mem_read(entry_point, &mut entry_code) {
        let has_code = entry_code.iter().any(|&b| b != 0);
        log::info!("  Entry point has code: {} (first bytes: {:02x?})", 
                 has_code, &entry_code[..8]);
        
        if !has_code {
            log::info!("  ⚠️  Entry point appears to be unmapped - this may be a packed executable");
            log::info!("      Consider using a different unpacking approach or manual analysis");
        }
    }
    
    // Set up stack
    if STACK_BASE >= max_addr || STACK_BASE + STACK_SIZE as u64 <= min_addr {
        emu.mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)?;
        log::info!("  Stack: 0x{:016x} - 0x{:016x}", STACK_BASE, STACK_BASE + STACK_SIZE as u64);
    }
    
    // Set up heap (basic)
    if HEAP_BASE >= max_addr || HEAP_BASE + HEAP_SIZE as u64 <= min_addr {
        emu.mem_map(HEAP_BASE, HEAP_SIZE, Permission::READ | Permission::WRITE)?;
        log::info!("  Heap: 0x{:016x} - 0x{:016x}", HEAP_BASE, HEAP_BASE + HEAP_SIZE as u64);
    }
    
    Ok(())
}