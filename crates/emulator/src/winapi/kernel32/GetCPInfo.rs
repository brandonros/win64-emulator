use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::Globalization::CPINFO;

use crate::emulation::memory;

pub fn GetCPInfo(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers (x64 calling convention)
    let code_page = emu.reg_read(RegisterX86::RCX)? as u32;  // UINT CodePage
    let cpinfo_ptr = emu.reg_read(RegisterX86::RDX)?;        // LPCPINFO lpCPInfo
    
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
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}