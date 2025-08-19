use crate::{loader_error::LoaderError, pe64_emulator::PE64Emulator};

mod loaded_pe;
mod loader_error;
mod structs;
mod pe64_emulator;

// Example usage and testing
fn main() -> Result<(), LoaderError> {
    println!("🔧 PE64 Loader with IAT Parsing");
    println!("=================================\n");
    
    // Example: Load and analyze a PE file
    let pe_path = "./assets/enigma_test_protected.exe";
    
    println!("📁 Loading PE file: {}", pe_path);
    
    match PE64Emulator::new(pe_path) {
        Ok(mut emulator) => {
            println!("\n✅ PE file loaded successfully!");
            
            // Show imported functions
            let imports = emulator.get_imports();
            if !imports.is_empty() {
                println!("\n📚 Imported Functions:");
                let mut current_dll = "";
                for import in imports {
                    if import.dll_name() != current_dll {
                        println!("  {}:", import.dll_name());
                        current_dll = &import.dll_name();
                    }
                    println!("    - {} (IAT: 0x{:016x})", import.function_name(), import.iat_address());
                }
            }
            
            // Look for specific symbols
            if let Some(main_addr) = emulator.find_symbol("main") {
                println!("🎯 Found 'main' symbol at: 0x{:016x}", main_addr);
            }
            
            // Start execution with a limit
            println!("\n⚡ Starting emulation...");
            emulator.run(0)?; // Just run 100 instructions to see what happens
            
        }
        Err(e) => {
            println!("❌ Failed to load PE file: {}", e);
            
            println!("\n💡 This loader now parses:");
            println!("   ✅ PE sections and headers");
            println!("   ✅ Import Address Table (IAT)");
            println!("   ✅ Imported DLLs and functions");
            println!("   ✅ Shows IAT addresses for patching");
        }
    }
    
    Ok(())
}