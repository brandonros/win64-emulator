use unicorn_engine::{Unicorn, RegisterX86};

pub fn FindResourceA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HRSRC FindResourceA(
    //   HMODULE hModule,  // RCX
    //   LPCSTR  lpName,   // RDX
    //   LPCSTR  lpType    // R8
    // )
    
    let h_module = emu.reg_read(RegisterX86::RCX)?;
    let lp_name = emu.reg_read(RegisterX86::RDX)?;
    let lp_type = emu.reg_read(RegisterX86::R8)?;
    
    log::info!("[FindResourceA] hModule: 0x{:x}", h_module);
    log::info!("[FindResourceA] lpName: 0x{:x}", lp_name);
    log::info!("[FindResourceA] lpType: 0x{:x}", lp_type);
    
    // Check if lpName is an integer resource ID or a string
    let resource_name = if lp_name < 0x10000 {
        // Integer resource ID
        format!("#{}", lp_name)
    } else if lp_name != 0 {
        // Try to read as string
        match crate::emulation::memory::read_string_from_memory(emu, lp_name) {
            Ok(name) => name,
            Err(_) => {
                log::warn!("[FindResourceA] Failed to read resource name string");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else {
        log::warn!("[FindResourceA] NULL resource name");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    };
    
    // Check if lpType is an integer resource ID or a string
    let resource_type = if lp_type < 0x10000 {
        // Integer resource ID
        format!("#{}", lp_type)
    } else if lp_type != 0 {
        // Try to read as string
        match crate::emulation::memory::read_string_from_memory(emu, lp_type) {
            Ok(type_name) => type_name,
            Err(_) => {
                log::warn!("[FindResourceA] Failed to read resource type string");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else {
        log::warn!("[FindResourceA] NULL resource type");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    };
    
    log::info!("[FindResourceA] Looking for resource: Name='{}', Type='{}'", 
              resource_name, resource_type);
    
    // In a real implementation, this would:
    // - Search the PE resource directory
    // - Find the specific resource by type and name
    // - Return a handle to the resource
    
    // Common resource type IDs
    const RT_VERSION: u64 = 16;
    const RT_MANIFEST: u64 = 24;
    const RT_ICON: u64 = 3;
    const RT_DIALOG: u64 = 5;
    const RT_STRING: u64 = 6;
    const RT_RCDATA: u64 = 10;
    
    // For mock implementation, simulate finding common resources
    let found = match lp_type {
        RT_VERSION if lp_name == 1 => true,  // Version resource with ID 1 is common
        RT_MANIFEST if lp_name == 1 || lp_name == 2 => true,  // Manifest IDs 1 or 2
        RT_ICON if lp_name >= 100 && lp_name <= 200 => true,  // Icon IDs in range
        RT_DIALOG if lp_name >= 1000 && lp_name <= 2000 => true,  // Dialog IDs in range
        RT_STRING | RT_RCDATA => true,  // These are commonly present
        _ => {
            // Random chance of finding other resources
            log::warn!("[FindResourceA] Mock: Resource type {} not specifically handled", lp_type);
            false
        }
    };
    
    if found {
        // Generate a mock resource handle
        // HRSRC is typically a pointer-like value
        static mut NEXT_RESOURCE_HANDLE: u64 = 0x500000;
        let resource_handle = unsafe {
            NEXT_RESOURCE_HANDLE += 0x100;
            NEXT_RESOURCE_HANDLE
        };
        
        log::info!("[FindResourceA] Resource found! Returning handle: 0x{:x}", resource_handle);
        emu.reg_write(RegisterX86::RAX, resource_handle)?;
    } else {
        log::info!("[FindResourceA] Resource not found");
        emu.reg_write(RegisterX86::RAX, 0)?; // NULL - resource not found
    }
    
    log::warn!("[FindResourceA] Mock implementation - not actually searching PE resources");
    
    Ok(())
}