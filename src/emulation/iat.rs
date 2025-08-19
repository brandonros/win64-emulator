use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, RwLock};
use unicorn_engine::{uc_error, Permission, Unicorn};
use crate::pe::{LoadedPE, MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};
use crate::winapi::module_registry::MODULE_REGISTRY;

// Global IAT function map for the hook to access
pub static IAT_FUNCTION_MAP: LazyLock<Arc<RwLock<HashMap<u64, (String, String)>>>> = 
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

pub fn setup_iat(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n📌 Setting up Import Address Table:");
    
    // Map memory for mock functions if we have any IAT entries
    if !pe.iat_entries().is_empty() {
        emu.mem_map(MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE, Permission::READ | Permission::EXEC)?;
        
        // Clear and populate the global IAT function map
        {
            let mut map = IAT_FUNCTION_MAP.write().unwrap();
            map.clear();
            
            // Track unique DLLs we encounter
            let mut seen_dlls = HashSet::new();
            
            // Write resolved addresses to IAT
            for entry in pe.iat_entries() {
                // Write the resolved address to the IAT entry
                let resolved_addr_bytes = entry.resolved_address.to_le_bytes();
                emu.mem_write(entry.iat_address, &resolved_addr_bytes)?;
                
                // Add to our global map for the hook to use
                map.insert(
                    entry.resolved_address,
                    (entry.import.dll_name().to_string(), 
                     entry.import.function_name().to_string())
                );
                
                // Track this DLL
                seen_dlls.insert(entry.import.dll_name().to_lowercase());
                
                log::info!("  IAT[0x{:016x}] = 0x{:016x} ({}!{})", 
                         entry.iat_address, entry.resolved_address, 
                         entry.import.dll_name(), entry.import.function_name());
            }
            
            // Ensure all imported DLLs are registered in the module registry
            // The registry already has common system DLLs pre-registered,
            // but we log which ones are actually used
            for dll_name in seen_dlls {
                if MODULE_REGISTRY.read().unwrap().get_module_handle(Some(&dll_name)).is_none() {
                    log::warn!("  ⚠️  DLL '{}' is imported but not in module registry", dll_name);
                    // Could dynamically register it here if needed
                }
            }
        }
        
        log::info!("  Populated {} IAT entries", pe.iat_entries().len());
    } else {
        log::info!("  No IAT entries to populate");
    }
    
    Ok(())
}