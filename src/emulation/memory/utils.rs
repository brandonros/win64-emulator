use unicorn_engine::{uc_error, Unicorn};

// String reading utilities

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

// Memory write utilities

pub fn write_word_le(emu: &mut Unicorn<()>, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_word_be(emu: &mut Unicorn<()>, addr: u64, value: u16) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn write_dword_le(emu: &mut Unicorn<()>, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_dword_be(emu: &mut Unicorn<()>, addr: u64, value: u32) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}

pub fn write_qword_le(emu: &mut Unicorn<()>, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_le_bytes()).unwrap();
}

#[allow(dead_code)]
pub fn write_qword_be(emu: &mut Unicorn<()>, addr: u64, value: u64) {
    emu.mem_write(addr, &value.to_be_bytes()).unwrap();
}