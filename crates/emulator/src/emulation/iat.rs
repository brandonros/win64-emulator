use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use unicorn_engine::{uc_error, Permission, Unicorn};
use crate::pe::constants::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};
use crate::pe::{LoadedPE, MODULE_REGISTRY};

// Global IAT function map for the hook to access
pub static IAT_FUNCTION_MAP: LazyLock<Arc<RwLock<HashMap<u64, (String, String)>>>> = 
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

pub fn setup_iat(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n📌 Setting up Import Address Table:");
    
    // Map memory for mock functions if we have any IAT entries
    if !pe.iat_entries().is_empty() {
        emu.mem_map(MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE, Permission::READ | Permission::EXEC)?;
        
        // Populate the global IAT function map
        {
            let mut map = IAT_FUNCTION_MAP.write().unwrap();
            
            // Write resolved addresses to IAT
            for entry in pe.iat_entries() {
                // The resolved address should already be set correctly from LoadedPE
                // (either to actual DLL export or mock address)
                let resolved_address = entry.resolved_address;
                
                // Write the resolved address to the IAT entry
                let resolved_addr_bytes = resolved_address.to_le_bytes();
                emu.mem_write(entry.iat_address, &resolved_addr_bytes)?;
                
                // Add to our global map for the hook to use
                map.insert(
                    resolved_address,
                    (entry.import.dll_name().to_string(), 
                     entry.import.function_name().to_string())
                );
                
                // Verify DLL is registered (on first occurrence only)
                let dll_name = entry.import.dll_name().to_lowercase();
                if MODULE_REGISTRY.get_module_handle(Some(&dll_name)).is_none() {
                    panic!("  ⚠️  DLL '{}' is imported but not in module registry", dll_name);
                }
                
                log::info!("  IAT[0x{:016x}] = 0x{:016x} ({}!{})", 
                         entry.iat_address, resolved_address, 
                         entry.import.dll_name(), entry.import.function_name());
            }
        }
        
        log::info!("  Populated {} IAT entries", pe.iat_entries().len());
    } else {
        log::info!("  No IAT entries to populate");
    }
    
    Ok(())
}

pub fn patch_iat(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n🔧 Patching IAT with actual DLL exports:");
    
    let mut patched_count = 0;
    let mut map = IAT_FUNCTION_MAP.write().unwrap();
    
    for entry in pe.iat_entries() {
        let dll_name = entry.import.dll_name().to_lowercase();
        let func_name = entry.import.function_name();
        
        // Try to resolve to actual DLL export
        if let Some(actual_address) = MODULE_REGISTRY.get_module_handle(Some(&dll_name))
            .and_then(|handle| MODULE_REGISTRY.get_module_by_handle(handle))
            .and_then(|module| module.get_proc_address(func_name)) {
            
            // Check if this is different from what's currently in the IAT
            if actual_address != entry.resolved_address {
                log::info!("  Patching {}!{}: 0x{:x} -> 0x{:x}", 
                         dll_name, func_name, entry.resolved_address, actual_address);
                
                // Write the actual address to the IAT
                let actual_addr_bytes = actual_address.to_le_bytes();
                emu.mem_write(entry.iat_address, &actual_addr_bytes)?;
                
                // Update our map - remove old entry and add new one
                map.remove(&entry.resolved_address);
                map.insert(
                    actual_address,
                    (dll_name.clone(), func_name.to_string())
                );
                
                patched_count += 1;
            }
        }
    }
    
    if patched_count > 0 {
        log::info!("  Patched {} IAT entries with actual DLL exports", patched_count);
    } else {
        log::info!("  No IAT entries needed patching");
    }
    
    Ok(())
}