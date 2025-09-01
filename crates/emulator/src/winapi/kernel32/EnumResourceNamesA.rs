use unicorn_engine::{Unicorn, RegisterX86};

pub fn EnumResourceNamesA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL EnumResourceNamesA(
    //   HMODULE          hModule,     // RCX
    //   LPCSTR           lpType,      // RDX
    //   ENUMRESNAMEPROCA lpEnumFunc,  // R8
    //   LONG_PTR         lParam       // R9
    // )
    
    let h_module = emu.reg_read(RegisterX86::RCX)?;
    let lp_type = emu.reg_read(RegisterX86::RDX)?;
    let enum_func = emu.reg_read(RegisterX86::R8)?;
    let l_param = emu.reg_read(RegisterX86::R9)?;
    
    log::info!("[EnumResourceNamesA] hModule: 0x{:x}", h_module);
    log::info!("[EnumResourceNamesA] lpType: 0x{:x}", lp_type);
    log::info!("[EnumResourceNamesA] lpEnumFunc: 0x{:x}", enum_func);
    log::info!("[EnumResourceNamesA] lParam: 0x{:x}", l_param);
    
    // Check for NULL callback
    if enum_func == 0 {
        log::warn!("[EnumResourceNamesA] NULL callback function");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Check if lpType is an integer resource ID or a string
    let resource_type = if lp_type < 0x10000 {
        // Integer resource ID
        log::info!("[EnumResourceNamesA] Resource type ID: {}", lp_type);
        format!("#{}", lp_type)
    } else {
        // Try to read as string
        match crate::emulation::memory::read_string_from_memory(emu, lp_type) {
            Ok(type_name) => {
                log::info!("[EnumResourceNamesA] Resource type name: '{}'", type_name);
                type_name
            }
            Err(_) => {
                log::warn!("[EnumResourceNamesA] Failed to read resource type string");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    };
    
    // In a real implementation, this would:
    // - Parse the PE resource directory of the module
    // - Find all resources of the specified type
    // - Call the callback function for each resource name
    // - Stop if the callback returns FALSE
    
    // Common resource types
    const RT_VERSION: u64 = 16;
    const RT_MANIFEST: u64 = 24;
    const RT_ICON: u64 = 3;
    const RT_DIALOG: u64 = 5;
    
    log::warn!("[EnumResourceNamesA] Mock implementation - simulating resource names");
    
    // Simulate resource names based on type
    let mock_names: Vec<u64> = match lp_type {
        RT_VERSION => {
            // Version resources typically have ID 1
            vec![1]
        }
        RT_MANIFEST => {
            // Manifest resources often have IDs 1, 2, or specific values
            vec![1, 2]
        }
        RT_ICON => {
            // Icons might have multiple IDs
            vec![101, 102, 103]
        }
        RT_DIALOG => {
            // Dialog IDs
            vec![1000, 1001]
        }
        _ => {
            // For unknown types, provide a default resource
            vec![1]
        }
    };
    
    for resource_name in &mock_names {
        log::info!("[EnumResourceNamesA] Calling callback for resource name: {}", resource_name);
        
        // The callback has signature: BOOL EnumResNameProc(HMODULE, LPCSTR, LPSTR, LONG_PTR)
        // We need to call it with:
        // - RCX = hModule
        // - RDX = lpType (resource type)
        // - R8 = lpName (resource name - can be integer ID or string)
        // - R9 = lParam
        
        // Save current context
        let saved_rip = emu.reg_read(RegisterX86::RIP)?;
        let saved_rsp = emu.reg_read(RegisterX86::RSP)?;
        
        // Set up parameters for callback
        emu.reg_write(RegisterX86::RCX, h_module)?;
        emu.reg_write(RegisterX86::RDX, lp_type)?;
        emu.reg_write(RegisterX86::R8, *resource_name)?; // Integer resource name
        emu.reg_write(RegisterX86::R9, l_param)?;
        
        // Simulate calling the callback
        // In a real implementation, we'd:
        // 1. Push return address
        // 2. Jump to callback
        // 3. Get return value
        
        // For mock, we'll just assume the callback returns TRUE to continue
        log::info!("[EnumResourceNamesA] Mock: Assuming callback returns TRUE");
        
        // Restore context
        emu.reg_write(RegisterX86::RIP, saved_rip)?;
        emu.reg_write(RegisterX86::RSP, saved_rsp)?;
    }
    
    // Return TRUE - enumeration completed successfully
    log::info!("[EnumResourceNamesA] Enumeration complete for type: {}", resource_type);
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}