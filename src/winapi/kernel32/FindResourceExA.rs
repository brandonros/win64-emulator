use unicorn_engine::{Unicorn, RegisterX86};

pub fn FindResourceExA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HRSRC FindResourceExA(
    //   HMODULE hModule,    // RCX
    //   LPCSTR  lpType,     // RDX
    //   LPCSTR  lpName,     // R8
    //   WORD    wLanguage   // R9 (low word only for WORD)
    // )
    
    let h_module = emu.reg_read(RegisterX86::RCX)?;
    let lp_type = emu.reg_read(RegisterX86::RDX)?;
    let lp_name = emu.reg_read(RegisterX86::R8)?;
    let w_language = (emu.reg_read(RegisterX86::R9)? & 0xFFFF) as u16;
    
    log::info!("[FindResourceExA] hModule: 0x{:x}", h_module);
    log::info!("[FindResourceExA] lpType: 0x{:x}", lp_type);
    log::info!("[FindResourceExA] lpName: 0x{:x}", lp_name);
    log::info!("[FindResourceExA] wLanguage: 0x{:04x}", w_language);
    
    // Check if lpType is an integer resource ID or a string
    let resource_type = if lp_type < 0x10000 {
        // Integer resource ID
        format!("#{}", lp_type)
    } else if lp_type != 0 {
        // Try to read as string
        match crate::emulation::memory::read_string_from_memory(emu, lp_type) {
            Ok(type_name) => type_name,
            Err(_) => {
                log::warn!("[FindResourceExA] Failed to read resource type string");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else {
        log::warn!("[FindResourceExA] NULL resource type");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    };
    
    // Check if lpName is an integer resource ID or a string
    let resource_name = if lp_name < 0x10000 {
        // Integer resource ID
        format!("#{}", lp_name)
    } else if lp_name != 0 {
        // Try to read as string
        match crate::emulation::memory::read_string_from_memory(emu, lp_name) {
            Ok(name) => name,
            Err(_) => {
                log::warn!("[FindResourceExA] Failed to read resource name string");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else {
        log::warn!("[FindResourceExA] NULL resource name");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    };
    
    // Language IDs
    const LANG_NEUTRAL: u16 = 0x00;
    const LANG_ENGLISH_US: u16 = 0x0409;
    const MAKELANGID_NEUTRAL_SUBLANG_NEUTRAL: u16 = 0x0000;
    
    let language_name = match w_language {
        LANG_NEUTRAL | MAKELANGID_NEUTRAL_SUBLANG_NEUTRAL => "NEUTRAL",
        LANG_ENGLISH_US => "ENGLISH_US",
        _ => "CUSTOM",
    };
    
    log::info!("[FindResourceExA] Looking for resource: Type='{}', Name='{}', Language='{}'", 
              resource_type, resource_name, language_name);
    
    // In a real implementation, this would:
    // - Search the PE resource directory
    // - Find the specific resource by type, name, and language
    // - Return a handle to the resource
    
    // Common resource type IDs
    const RT_VERSION: u64 = 16;
    const RT_MANIFEST: u64 = 24;
    const RT_ICON: u64 = 3;
    const RT_DIALOG: u64 = 5;
    const RT_STRING: u64 = 6;
    const RT_RCDATA: u64 = 10;
    
    // For mock implementation, simulate finding common resources
    // Accept neutral language or English US for most resources
    let language_ok = w_language == LANG_NEUTRAL || 
                     w_language == LANG_ENGLISH_US || 
                     w_language == MAKELANGID_NEUTRAL_SUBLANG_NEUTRAL;
    
    let found = if !language_ok {
        // Wrong language
        log::info!("[FindResourceExA] Language not available for this resource");
        false
    } else {
        // Check resource type and name
        match lp_type {
            RT_VERSION if lp_name == 1 => true,  // Version resource with ID 1
            RT_MANIFEST if lp_name == 1 || lp_name == 2 => true,  // Manifest IDs 1 or 2
            RT_ICON if lp_name >= 100 && lp_name <= 200 => true,  // Icon IDs in range
            RT_DIALOG if lp_name >= 1000 && lp_name <= 2000 => true,  // Dialog IDs in range
            RT_STRING | RT_RCDATA => true,  // These are commonly present
            _ => {
                log::warn!("[FindResourceExA] Mock: Resource type {} not specifically handled", lp_type);
                false
            }
        }
    };
    
    if found {
        // Generate a mock resource handle
        // Make it different from FindResourceA by incorporating language
        static mut NEXT_RESOURCE_HANDLE: u64 = 0x600000;
        let resource_handle = unsafe {
            NEXT_RESOURCE_HANDLE += 0x100;
            // Incorporate language into handle for uniqueness
            NEXT_RESOURCE_HANDLE + (w_language as u64)
        };
        
        log::info!("[FindResourceExA] Resource found! Returning handle: 0x{:x}", resource_handle);
        emu.reg_write(RegisterX86::RAX, resource_handle)?;
    } else {
        log::info!("[FindResourceExA] Resource not found for specified language");
        emu.reg_write(RegisterX86::RAX, 0)?; // NULL - resource not found
    }
    
    log::warn!("[FindResourceExA] Mock implementation - not actually searching PE resources");
    
    Ok(())
}