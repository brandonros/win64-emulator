use crate::emulation::engine::{EmulatorEngine, EmulatorError};
use crate::emulation::memory::{STACK_BASE, STACK_SIZE, HEAP_BASE, HEAP_SIZE, TEB_BASE, TEB_SIZE, PEB_BASE, PEB_SIZE};

// String reading utilities

pub fn read_string_from_memory(emu: &mut dyn EmulatorEngine, addr: u64) -> Result<String, EmulatorError> {
    let mut bytes = Vec::new();
    let mut current_addr = addr;
    
    // Read up to N bytes or until we hit a null terminator
    for _ in 0..4096 {
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
pub fn read_wide_string_from_memory(emu: &mut dyn EmulatorEngine, addr: u64) -> Result<String, EmulatorError> {
    let mut bytes = Vec::new();
    let mut current_addr = addr;
    
    // Read up to N wide chars or until we hit a null terminator
    for _ in 0..4096 {
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

// Memory write utilities

pub fn write_string_to_memory(emu: &mut dyn EmulatorEngine, addr: u64, s: &str) -> Result<(), EmulatorError> {
    // Write the string bytes including null terminator
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0); // Add null terminator
    
    emu.mem_write(addr, &bytes)?;
    
    Ok(())
}

#[allow(dead_code)]
pub fn write_wide_string_to_memory(emu: &mut dyn EmulatorEngine, addr: u64, s: &str) -> Result<(), EmulatorError> {
    // Convert string to UTF-16 and write including null terminator
    let mut wide_chars: Vec<u16> = s.encode_utf16().collect();
    wide_chars.push(0); // Add null terminator
    
    // Convert to bytes
    let mut bytes = Vec::new();
    for wchar in wide_chars {
        bytes.extend_from_slice(&wchar.to_le_bytes());
    }
    
    emu.mem_write(addr, &bytes)?;
    
    Ok(())
}

#[allow(dead_code)]
pub fn write_word_le(emu: &mut dyn EmulatorEngine, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_word_be(emu: &mut dyn EmulatorEngine, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_dword_le(emu: &mut dyn EmulatorEngine, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_dword_be(emu: &mut dyn EmulatorEngine, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_qword_le(emu: &mut dyn EmulatorEngine, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_qword_be(emu: &mut dyn EmulatorEngine, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn write_struct<T>(emu: &mut dyn EmulatorEngine, addr: u64, data: &T) -> Result<(), EmulatorError> {
    let size = std::mem::size_of::<T>();
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            data as *const T as *const u8,
            size
        )
    };
    emu.mem_write(addr, bytes)
}

pub fn read_struct<T>(emu: &mut dyn EmulatorEngine, addr: u64) -> Result<T, EmulatorError> {
    let size = std::mem::size_of::<T>();
    let mut bytes = vec![0u8; size];
    emu.mem_read(addr, &mut bytes)?;
    
    let data: T = unsafe {
        std::ptr::read(bytes.as_ptr() as *const T)
    };
    
    Ok(data)
}

#[derive(Debug)]
pub enum MemoryRegion {
    Stack,
    Heap,
    Tls,
    Teb,
    Peb,
    Unknown
}

pub fn determine_memory_region(addr: u64) -> MemoryRegion {
    if addr >= STACK_BASE && addr < STACK_BASE + STACK_SIZE as u64 {
        MemoryRegion::Stack
    } else if addr >= HEAP_BASE && addr < HEAP_BASE + HEAP_SIZE as u64 {
        MemoryRegion::Heap
    } else if addr >= TEB_BASE && addr < TEB_BASE + TEB_SIZE as u64 {
        let tls_start = TEB_BASE + 0x1480;
        let tls_end = tls_start + (64 * 8);
        if addr >= tls_start && addr < tls_end {
            MemoryRegion::Tls
        } else {
            MemoryRegion::Teb
        }
    } else if addr >= PEB_BASE && addr < PEB_BASE + PEB_SIZE as u64 {
        MemoryRegion::Peb
    } else {
        MemoryRegion::Unknown
    }
}
