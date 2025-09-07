use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use windows_sys::Win32::Globalization::CPINFO;

pub fn GetCPInfo(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let code_page = emu.reg_read(X86Register::RCX)? as u32;  // UINT CodePage
    let cpinfo_ptr = emu.reg_read(X86Register::RDX)?;        // LPCPINFO lpCPInfo
    
    log::info!("[GetCPInfo] CodePage: {}, cpinfo_ptr: 0x{:x}", code_page, cpinfo_ptr);
    
    if cpinfo_ptr > 0 {
        // Create mock CPINFO structure based on the requested code page
        let mock_cpinfo = match code_page {
            437 | 1252 | 65001 => {  // Common code pages (OEM US, Windows-1252, UTF-8)
                CPINFO {
                    MaxCharSize: if code_page == 65001 { 4 } else { 1 },  // UTF-8 can be up to 4 bytes
                    DefaultChar: [b'?', 0],  // Default replacement character
                    LeadByte: [0; 12],       // No lead bytes for these code pages
                }
            }
            _ => {
                // Generic single-byte code page
                CPINFO {
                    MaxCharSize: 1,
                    DefaultChar: [b'?', 0],
                    LeadByte: [0; 12],
                }
            }
        };
        
        memory::write_struct(emu, cpinfo_ptr, &mock_cpinfo)?;
    }
    
    // Return TRUE (1) for success
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}