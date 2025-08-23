use unicorn_engine::{Unicorn, RegisterX86};

pub fn EnumResourceTypesA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL EnumResourceTypesA(
    //   HMODULE          hModule,     // RCX
    //   ENUMRESTYPEPROCA lpEnumFunc,  // RDX
    //   LONG_PTR         lParam       // R8
    // )
    
    let h_module = emu.reg_read(RegisterX86::RCX)?;
    let enum_func = emu.reg_read(RegisterX86::RDX)?;
    let l_param = emu.reg_read(RegisterX86::R8)?;
    
    log::info!("[EnumResourceTypesA] hModule: 0x{:x}", h_module);
    log::info!("[EnumResourceTypesA] lpEnumFunc: 0x{:x}", enum_func);
    log::info!("[EnumResourceTypesA] lParam: 0x{:x}", l_param);
    
    // Check for NULL callback
    if enum_func == 0 {
        log::warn!("[EnumResourceTypesA] NULL callback function");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Parse the PE resource directory of the module
    // - Find all resource types
    // - Call the callback function for each type
    // - Stop if the callback returns FALSE
    
    // Common resource types (RT_*)
    const RT_CURSOR: u32 = 1;
    const RT_BITMAP: u32 = 2;
    const RT_ICON: u32 = 3;
    const RT_MENU: u32 = 4;
    const RT_DIALOG: u32 = 5;
    const RT_STRING: u32 = 6;
    const RT_FONTDIR: u32 = 7;
    const RT_FONT: u32 = 8;
    const RT_ACCELERATOR: u32 = 9;
    const RT_RCDATA: u32 = 10;
    const RT_MESSAGETABLE: u32 = 11;
    const RT_GROUP_CURSOR: u32 = 12;
    const RT_GROUP_ICON: u32 = 14;
    const RT_VERSION: u32 = 16;
    const RT_MANIFEST: u32 = 24;
    
    // For mock implementation, we'll simulate a few common resource types
    // In reality, we'd need to parse the PE file's resource section
    
    log::warn!("[EnumResourceTypesA] Mock implementation - simulating common resource types");
    
    // Simulate having a version resource and a manifest
    let mock_types = [RT_VERSION, RT_MANIFEST];
    
    for resource_type in &mock_types {
        log::info!("[EnumResourceTypesA] Calling callback for resource type: {}", resource_type);
        
        // The callback has signature: BOOL EnumResTypeProc(HMODULE, LPSTR, LONG_PTR)
        // We need to call it with:
        // - RCX = hModule
        // - RDX = lpType (resource type as LPSTR - can be integer ID or string)
        // - R8 = lParam
        
        // For integer resource IDs, we pass them directly as "string pointers"
        // Windows convention: if high word is 0, it's an integer ID
        
        // Save current context
        let saved_rip = emu.reg_read(RegisterX86::RIP)?;
        let saved_rsp = emu.reg_read(RegisterX86::RSP)?;
        
        // Set up parameters for callback
        emu.reg_write(RegisterX86::RCX, h_module)?;
        emu.reg_write(RegisterX86::RDX, *resource_type as u64)?; // Integer resource ID
        emu.reg_write(RegisterX86::R8, l_param)?;
        
        // Simulate calling the callback
        // In a real implementation, we'd:
        // 1. Push return address
        // 2. Jump to callback
        // 3. Get return value
        
        // For mock, we'll just assume the callback returns TRUE to continue
        log::info!("[EnumResourceTypesA] Mock: Assuming callback returns TRUE");
        
        // Restore context
        emu.reg_write(RegisterX86::RIP, saved_rip)?;
        emu.reg_write(RegisterX86::RSP, saved_rsp)?;
    }
    
    // Return TRUE - enumeration completed successfully
    log::info!("[EnumResourceTypesA] Enumeration complete");
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}