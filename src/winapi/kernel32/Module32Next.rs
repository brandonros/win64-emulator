use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32;
use crate::emulation::memory::utils::write_struct;
use crate::pe::module_registry::MODULE_REGISTRY;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

/*
Module32Next function (tlhelp32.h)
08/08/2022
Retrieves information about the next module associated with a process or thread.

Syntax
C++

Copy
BOOL Module32Next(
  [in]  HANDLE          hSnapshot,
  [out] LPMODULEENTRY32 lpme
);
Parameters
[in] hSnapshot

A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.

[out] lpme

A pointer to a MODULEENTRY32 structure.

Return value
Returns TRUE if the next entry of the module list has been copied to the buffer or FALSE otherwise. The ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no more modules exist.
*/

// Track module enumeration state per snapshot handle
static SNAPSHOT_MODULE_STATE: LazyLock<RwLock<HashMap<u64, usize>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

pub fn Module32Next(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL Module32Next(
    //   [in]  HANDLE          hSnapshot,  // RCX
    //   [out] LPMODULEENTRY32 lpme        // RDX
    // )
    
    let h_snapshot = emu.reg_read(X86Register::RCX)?;
    let lpme = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[Module32Next] hSnapshot: 0x{:x}", h_snapshot);
    log::info!("[Module32Next] lpme: 0x{:x}", lpme);
    
    // Check for NULL module entry pointer
    if lpme == 0 {
        log::error!("[Module32Next] NULL lpme pointer");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Check for invalid snapshot handle
    if h_snapshot == 0 || h_snapshot == 0xFFFFFFFFFFFFFFFF {
        log::error!("[Module32Next] Invalid snapshot handle");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Read the dwSize field to validate the structure
    let mut size_bytes = [0u8; 4];
    match emu.mem_read(lpme, &mut size_bytes) {
        Ok(_) => {},
        Err(e) => {
            log::error!("[Module32Next] Failed to read dwSize: {:?}", e);
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    let dw_size = u32::from_le_bytes(size_bytes);
    
    // Validate structure size
    if dw_size < std::mem::size_of::<MODULEENTRY32>() as u32 {
        log::error!("[Module32Next] Invalid dwSize: {} (expected at least {})", 
                   dw_size, std::mem::size_of::<MODULEENTRY32>());
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Get all modules from the registry
    let modules = MODULE_REGISTRY.get_all_modules();
    
    if modules.is_empty() {
        log::error!("[Module32Next] No modules registered in the module registry");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Get or initialize the enumeration state for this snapshot
    let mut state = SNAPSHOT_MODULE_STATE.write().unwrap();
    let current_index = state.entry(h_snapshot).or_insert(0);
    
    // Module32First should set index to 1, Module32Next continues from there
    // If this is the first call to Module32Next after Module32First, index should be 1
    if *current_index == 0 {
        *current_index = 1; // Skip the first module (already returned by Module32First)
    }
    
    // Check if we have more modules to enumerate
    if *current_index >= modules.len() {
        log::info!("[Module32Next] No more modules to enumerate (index {} >= {})", 
                  *current_index, modules.len());
        drop(state); // Release the lock before returning
        emu.reg_write(X86Register::RAX, 0)?; // FALSE - no more modules
        return Ok(());
    }
    
    // Get the next module
    let module = &modules[*current_index];
    *current_index += 1; // Move to next module for next call
    
    // Use the actual module name and construct a path
    let module_name = if module.name.ends_with(".dll") || module.name.ends_with(".exe") {
        module.name.clone()
    } else if module.name.contains("enigma") {
        format!("{}.exe", module.name)
    } else {
        format!("{}.dll", module.name)
    };
    
    let module_path = if module_name.ends_with(".exe") {
        format!("C:\\Program Files\\Application\\{}", module_name)
    } else {
        format!("C:\\Windows\\System32\\{}", module_name)
    };
    
    log::info!("[Module32Next] Returning module: {}", module.name);
    log::info!("  Base: 0x{:x}, Size: 0x{:x}", module.base_address, module.size);
    
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
        th32ModuleID: *current_index as u32,  // Use index as module ID
        th32ProcessID: 0x1000,  // Mock process ID
        GlblcntUsage: 1,  // Global usage count
        ProccntUsage: 1,  // Process usage count
        modBaseAddr: module.base_address as *mut u8,  // Actual base address from registry
        modBaseSize: module.size as u32,  // Actual module size from registry
        hModule: module.base_address as *mut _,  // Module handle (same as base address)
        szModule: sz_module,
        szExePath: sz_exe_path,
    };
    
    // Write the module entry to the provided buffer
    match write_struct(emu, lpme, &module_entry) {
        Ok(_) => {
            log::info!("[Module32Next] Successfully wrote module entry");
            log::info!("  Module: {}", module_name);
            log::info!("  Path: {}", module_path);
            log::info!("  Base Address: 0x{:x}", module_entry.modBaseAddr as u64);
            log::info!("  Base Size: 0x{:x}", module_entry.modBaseSize);
        }
        Err(e) => {
            log::error!("[Module32Next] Failed to write module entry: {:?}", e);
            drop(state); // Release the lock before returning
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    
    drop(state); // Release the lock
    
    // Return TRUE (success)
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}