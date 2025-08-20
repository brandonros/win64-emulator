use crate::loader_error::LoaderError;
use crate::emulation::Emulator;

mod pe;
mod loader_error;
mod emulation;
mod winapi;

// Example usage and testing
fn main() -> Result<(), LoaderError> {
    // console logger
    fast_log::init(fast_log::Config::new().console().chan_len(Some(100000))).unwrap();

    // file logger
    //fast_log::init(fast_log::Config::new().file("/tmp/win64-emulator.log").chan_len(Some(100000))).unwrap();

    log::info!("🔧 PE64 Loader with IAT Parsing");
    log::info!("=================================\n");
    
    // Example: Load and analyze a PE file
    let pe_path = "/Users/brandon/Desktop/win64-emulator/assets/enigma_test_protected.exe";
    
    log::info!("📁 Loading PE file: {}", pe_path);
    
    let mut emulator = Emulator::new(pe_path)?;

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
    emulator.run(0)?;

    // flush logger on exit
    log::logger().flush();
    
    Ok(())
}