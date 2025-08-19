use unicorn_engine::{uc_error, Permission, Unicorn};
use crate::pe::LoadedPE;

// Memory layout constants
pub const STACK_BASE: u64 = 0x7fff0000;
pub const STACK_SIZE: usize = 0x10000;
pub const HEAP_BASE: u64 = 0x10000000;
pub const HEAP_SIZE: usize = 0x100000;

// Thread Environment Block (TEB) and Process Environment Block (PEB)
pub const TEB_BASE: u64 = 0x7FFE0000;
pub const TEB_SIZE: usize = 0x2000;
pub const PEB_BASE: u64 = 0x7FFE2000;
pub const PEB_SIZE: usize = 0x1000;

// TLS (Thread Local Storage) constants
pub const TEB_TLS_SLOTS_OFFSET: u64 = 0x1480;  // Offset of TlsSlots[64] array in TEB
pub const TLS_MINIMUM_AVAILABLE: usize = 64;    // Number of TLS slots in TEB
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF; // Return value when no slots available

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

pub fn read_string_from_memory(emu: &mut Unicorn<()>, addr: u64) -> Result<String, uc_error> {
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

#[allow(dead_code)]
pub fn read_wide_string_from_memory(emu: &mut Unicorn<()>, addr: u64) -> Result<String, uc_error> {
    let mut bytes = Vec::new();
    let mut current_addr = addr;
    
    // Read up to 256 wide chars or until we hit a null terminator
    for _ in 0..256 {
        let mut wchar = [0u8; 2];
        emu.mem_read(current_addr, &mut wchar)?;
        
        let wide_char = u16::from_le_bytes(wchar);
        if wide_char == 0 {
            break;
        }
        
        bytes.push(wide_char);
        current_addr += 2;
    }
    
    Ok(String::from_utf16_lossy(&bytes))
}

pub fn write_word_le(emu: &mut Unicorn<()>, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

pub fn write_word_be(emu: &mut Unicorn<()>, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn write_dword_le(emu: &mut Unicorn<()>, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

pub fn write_dword_be(emu: &mut Unicorn<()>, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn write_qword_le(emu: &mut Unicorn<()>, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

pub fn write_qword_be(emu: &mut Unicorn<()>, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn setup_teb(emu: &mut Unicorn<'static, ()>) -> Result<(), uc_error> {
    log::info!("  Setting up TEB at 0x{:016x}", TEB_BASE);
    
    // Map TEB memory
    emu.mem_map(TEB_BASE, TEB_SIZE, Permission::READ | Permission::WRITE)?;
    
    // Initialize TEB with zeros
    let teb_data = vec![0u8; TEB_SIZE];
    emu.mem_write(TEB_BASE, &teb_data)?;
    
    // Write critical TEB fields for x64
    // Offset 0x08: StackBase (top of stack)
    let stack_top = STACK_BASE + STACK_SIZE as u64;
    emu.mem_write(TEB_BASE + 0x08, &stack_top.to_le_bytes())?;
    
    // Offset 0x10: StackLimit (bottom of stack)
    emu.mem_write(TEB_BASE + 0x10, &STACK_BASE.to_le_bytes())?;
    
    // Offset 0x30: Self pointer (linear address of TEB)
    emu.mem_write(TEB_BASE + 0x30, &TEB_BASE.to_le_bytes())?;
    
    // Offset 0x48: Thread ID (using our mock value)
    let thread_id: u64 = 0x1000;
    emu.mem_write(TEB_BASE + 0x48, &thread_id.to_le_bytes())?;
    
    // Offset 0x40: Process ID (mock value)
    let process_id: u64 = 0x100;
    emu.mem_write(TEB_BASE + 0x40, &process_id.to_le_bytes())?;
    
    // Offset 0x60: PEB pointer
    emu.mem_write(TEB_BASE + 0x60, &PEB_BASE.to_le_bytes())?;
    
    // Offset 0x1480: TlsSlots[64] array - initialize to zeros
    // The array is already zeroed when we initialized the TEB with zeros above,
    // but we'll explicitly document this for clarity
    // TlsSlots is a 64-element array of pointers (8 bytes each on x64)
    // Total size: 64 * 8 = 512 bytes
    log::info!("    TEB.TlsSlots = 0x{:016x} (64 slots initialized)", TEB_BASE + TEB_TLS_SLOTS_OFFSET);
    
    log::info!("    TEB.StackBase = 0x{:016x}", stack_top);
    log::info!("    TEB.StackLimit = 0x{:016x}", STACK_BASE);
    log::info!("    TEB.Self = 0x{:016x}", TEB_BASE);
    log::info!("    TEB.ProcessId = 0x{:x}", process_id);
    log::info!("    TEB.ThreadId = 0x{:x}", thread_id);
    log::info!("    TEB.Peb = 0x{:016x}", PEB_BASE);
    
    Ok(())
}

pub fn setup_peb(emu: &mut Unicorn<'static, ()>, image_base: u64) -> Result<(), uc_error> {
    log::info!("  Setting up PEB at 0x{:016x}", PEB_BASE);
    
    // Map PEB memory
    emu.mem_map(PEB_BASE, PEB_SIZE, Permission::READ | Permission::WRITE)?;
    
    // Initialize PEB with zeros
    let peb_data = vec![0u8; PEB_SIZE];
    emu.mem_write(PEB_BASE, &peb_data)?;
    
    // Write critical PEB fields for x64
    // Offset 0x10: ImageBaseAddress
    emu.mem_write(PEB_BASE + 0x10, &image_base.to_le_bytes())?;
    
    // Offset 0x03: BeingDebugged (set to 0 for not being debugged)
    emu.mem_write(PEB_BASE + 0x02, &[0u8])?;
    
    // Offset 0x0C: Ldr (we'll leave this null for now)
    // Offset 0x18: ProcessHeap (point to our heap)
    emu.mem_write(PEB_BASE + 0x18, &HEAP_BASE.to_le_bytes())?;
    
    log::info!("    PEB.ImageBaseAddress = 0x{:016x}", image_base);
    log::info!("    PEB.ProcessHeap = 0x{:016x}", HEAP_BASE);
    log::info!("    PEB.BeingDebugged = 0");
    
    Ok(())
}