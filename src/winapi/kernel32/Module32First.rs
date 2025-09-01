use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32;
use crate::emulation::memory::utils::write_struct;
use crate::pe::module_registry::MODULE_REGISTRY;

/*
Module32First function (tlhelp32.h)
02/22/2024
Retrieves information about the first module associated with a process.

Syntax
C++

Copy
BOOL Module32First(
  [in]      HANDLE          hSnapshot,
  [in, out] LPMODULEENTRY32 lpme
);
Parameters
[in] hSnapshot

A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.

[in, out] lpme

A pointer to a MODULEENTRY32 structure.

Return value
Returns TRUE if the first entry of the module list has been copied to the buffer or FALSE otherwise. The ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no modules exist or the snapshot does not contain module information.
*/

pub fn Module32First(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL Module32First(
    //   [in]      HANDLE          hSnapshot,  // RCX
    //   [in, out] LPMODULEENTRY32 lpme        // RDX
    // )
    
    let h_snapshot = emu.reg_read(RegisterX86::RCX)?;
    let lpme = emu.reg_read(RegisterX86::RDX)?;
    
    log::info!("[Module32First] hSnapshot: 0x{:x}", h_snapshot);
    log::info!("[Module32First] lpme: 0x{:x}", lpme);
    
    // Check for NULL module entry pointer
    if lpme == 0 {
        log::error!("[Module32First] NULL lpme pointer");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Check for invalid snapshot handle
    if h_snapshot == 0 || h_snapshot == 0xFFFFFFFFFFFFFFFF {
        log::error!("[Module32First] Invalid snapshot handle");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Read the dwSize field to validate the structure
    let mut size_bytes = [0u8; 4];
    match emu.mem_read(lpme, &mut size_bytes) {
        Ok(_) => {},
        Err(e) => {
            log::error!("[Module32First] Failed to read dwSize: {:?}", e);
            emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    let dw_size = u32::from_le_bytes(size_bytes);
    
    // Validate structure size
    if dw_size < std::mem::size_of::<MODULEENTRY32>() as u32 {
        log::error!("[Module32First] Invalid dwSize: {} (expected at least {})", 
                   dw_size, std::mem::size_of::<MODULEENTRY32>());
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    log::info!("[Module32First] dwSize: {}", dw_size);
    
    // Get the first module from the registry (typically the main executable)
    let modules = MODULE_REGISTRY.get_all_modules();
    
    if modules.is_empty() {
        log::error!("[Module32First] No modules registered in the module registry");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Find the main module (enigma_test_protected) or use the first module
    let main_module = modules.iter()
        .find(|m| m.name.contains("enigma_test_protected"))
        .or_else(|| modules.first())
        .unwrap();
    
    // Use the actual module name and construct a path
    let module_name = if main_module.name.ends_with(".exe") {
        main_module.name.clone()
    } else {
        format!("{}.exe", main_module.name)
    };
    let module_path = format!("C:\\Program Files\\Application\\{}", module_name);
    
    log::info!("[Module32First] Using module from registry: {}", main_module.name);
    log::info!("  Base: 0x{:x}, Size: 0x{:x}", main_module.base_address, main_module.size);
    
    // Convert strings to fixed-size arrays
    let mut sz_module = [0i8; 256];
    let mut sz_exe_path = [0i8; 260];
    
    // Copy module name
    for (i, byte) in module_name.bytes().enumerate() {
        if i < 255 {
            sz_module[i] = byte as i8;
        }
    }
    
    // Copy exe path
    for (i, byte) in module_path.bytes().enumerate() {
        if i < 259 {
            sz_exe_path[i] = byte as i8;
        }
    }
    
    // Create the module entry structure with real data from the registry
    let module_entry = MODULEENTRY32 {
        dwSize: dw_size,  // Preserve the caller's size
        th32ModuleID: 1,  // Module ID
        th32ProcessID: 0x1000,  // Mock process ID
        GlblcntUsage: 1,  // Global usage count
        ProccntUsage: 1,  // Process usage count
        modBaseAddr: main_module.base_address as *mut u8,  // Actual base address from registry
        modBaseSize: main_module.size as u32,  // Actual module size from registry
        hModule: main_module.base_address as *mut _,  // Module handle (same as base address)
        szModule: sz_module,
        szExePath: sz_exe_path,
    };
    
    // Write the module entry to the provided buffer
    match write_struct(emu, lpme, &module_entry) {
        Ok(_) => {
            log::info!("[Module32First] Successfully wrote first module entry");
            log::info!("  Module: {}", module_name);
            log::info!("  Path: {}", module_path);
            log::info!("  Base Address: 0x{:x}", module_entry.modBaseAddr as u64);
            log::info!("  Base Size: 0x{:x}", module_entry.modBaseSize);
            log::info!("  Process ID: 0x{:x}", module_entry.th32ProcessID);
        }
        Err(e) => {
            log::error!("[Module32First] Failed to write module entry: {:?}", e);
            emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    
    log::warn!("[Module32First] Mock implementation - returning first module entry");
    
    // Return TRUE (success)
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}