use crate::loader_error::LoaderError;
use crate::emulation::Emulator;
#[cfg(feature = "trace-instruction")]
use crate::emulation::tracing;

mod pe;
mod loader_error;
mod emulation;
mod winapi;

// Example usage and testing
fn main() -> Result<(), LoaderError> {
    // init tracer
    #[cfg(feature = "trace-instruction")]
    {
        tracing::init_tracing("/tmp/win64-emulator-trace.bin")?;
    }
    
    // console logger
    #[cfg(feature = "console-logger")]
    {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        //fast_log::init(fast_log::Config::new().console().chan_len(Some(100000))).unwrap();
    }

    // file logger
    #[cfg(feature = "file-logger")]
    {
        use std::fs::OpenOptions;
        let log_path = "/tmp/win64-emulator.log";
        let _ = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(log_path);
        fast_log::init(fast_log::Config::new().file(log_path).chan_len(Some(100000))).unwrap();

    }
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

    // Dump memory regions
    for region in emulator.get_emu().mem_regions().unwrap() {
        log::info!("Mapped region: 0x{:016x} - 0x{:016x} (size: 0x{:x})", 
                  region.begin, region.end, region.end - region.begin);
    }

    // Look for specific symbols
    if let Some(main_addr) = emulator.find_symbol("main") {
        log::info!("🎯 Found 'main' symbol at: 0x{:016x}", main_addr);
    }

    // Start execution with a limit
    log::info!("\n⚡ Starting emulation...");
    emulator.run(0)?;

    // flush logger on exit
    #[cfg(feature = "trace-instruction")]
    {
        tracing::flush_trace();
    }
    log::logger().flush();
    
    Ok(())
}