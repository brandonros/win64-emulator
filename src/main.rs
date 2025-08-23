use crate::loader_error::LoaderError;
use crate::emulation::Emulator;
#[cfg(feature = "trace-instruction")]
use crate::emulation::tracing;
use std::env;

mod pe;
mod loader_error;
mod emulation;
mod winapi;

fn print_usage() {
    println!("Usage: {} <PE_FILE_PATH>", env::args().nth(0).unwrap_or_else(|| "win64-emulator".to_string()));
    println!("\nExample:");
    println!("  {} /path/to/program.exe", env::args().nth(0).unwrap_or_else(|| "win64-emulator".to_string()));
    println!("  {} /path/to/library.dll", env::args().nth(0).unwrap_or_else(|| "win64-emulator".to_string()));
}

fn main() -> Result<(), LoaderError> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        print_usage();
        std::process::exit(1);
    }
    
    let pe_path = &args[1];

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

    // Look for specific symbols based on PE type
    if emulator.is_dll() {
        log::info!("📦 Loaded DLL successfully");
        if let Some(dllmain_addr) = emulator.find_symbol("DllMain") {
            log::info!("🎯 Found 'DllMain' symbol at: 0x{:016x}", dllmain_addr);
        }
    } else {
        log::info!("📦 Loaded EXE successfully");
        if let Some(main_addr) = emulator.find_symbol("main") {
            log::info!("🎯 Found 'main' symbol at: 0x{:016x}", main_addr);
        }
        if let Some(winmain_addr) = emulator.find_symbol("WinMain") {
            log::info!("🎯 Found 'WinMain' symbol at: 0x{:016x}", winmain_addr);
        }
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