use crate::{loader_error::LoaderError, pe64_emulator::PE64Emulator};

mod loaded_pe;
mod loader_error;
mod structs;
mod pe64_emulator;

// Example usage and testing
fn main() -> Result<(), LoaderError> {
    fast_log::init(fast_log::Config::new().console().chan_len(Some(1000000))).unwrap();

    log::info!("🔧 PE64 Loader with IAT Parsing");
    log::info!("=================================\n");
    
    // Example: Load and analyze a PE file
    let pe_path = "./assets/enigma_test_protected.exe";
    
    log::info!("📁 Loading PE file: {}", pe_path);
    
    match PE64Emulator::new(pe_path) {
        Ok(mut emulator) => {
            log::info!("\n✅ PE file loaded successfully!");
            
            // Show imported functions
            let imports = emulator.get_imports();
            if !imports.is_empty() {
                log::info!("\n📚 Imported Functions:");
                let mut current_dll = "";
                for import in imports {
                    if import.dll_name() != current_dll {
                        log::info!("  {}:", import.dll_name());
                        current_dll = &import.dll_name();
                    }
                    log::info!("    - {} (IAT: 0x{:016x})", import.function_name(), import.iat_address());
                }
            }
            
            // Look for specific symbols
            if let Some(main_addr) = emulator.find_symbol("main") {
                log::info!("🎯 Found 'main' symbol at: 0x{:016x}", main_addr);
            }
            
            // Start execution with a limit
            log::info!("\n⚡ Starting emulation...");
            emulator.run(0)?; // Just run 100 instructions to see what happens
            
        }
        Err(e) => {
            log::info!("❌ Failed to load PE file: {}", e);
            
            log::info!("\n💡 This loader now parses:");
            log::info!("   ✅ PE sections and headers");
            log::info!("   ✅ Import Address Table (IAT)");
            log::info!("   ✅ Imported DLLs and functions");
            log::info!("   ✅ Shows IAT addresses for patching");
        }
    }
    
    Ok(())
}