use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use crate::emulation::engine::EmulatorEngine;
use crate::loader_error::LoaderError;

pub fn dump_memory(
    emu: &mut dyn EmulatorEngine,
    output_dir: &Path,
) -> Result<(), LoaderError> {
    // Create output directory
    std::fs::create_dir_all(output_dir)
        .map_err(|e| LoaderError::IoError(e))?;
    
    let regions = emu.mem_regions()?;
    
    log::info!("📦 Dumping {} memory regions to separate files", regions.len());
    
    for (i, (begin, end)) in regions.iter().enumerate() {
        let size = (end - begin + 1) as usize;
        let mut buffer = vec![0u8; size];
        
        if let Ok(_) = emu.mem_read(*begin, &mut buffer) {
            let filename = format!("region_{:02}_{:016x}.bin", i, *begin);
            let filepath = output_dir.join(&filename);
            
            File::create(&filepath)?
                .write_all(&buffer)?;
            
            log::info!("  Saved region {} (0x{:016x} - 0x{:016x}) to {}", 
                i, *begin, *end, filename);
        }
    }
    
    // Write mapping info
    let info_path = output_dir.join("regions.txt");
    let mut info = File::create(&info_path)?;
    
    for (i, (begin, end)) in regions.iter().enumerate() {
        writeln!(info, "region_{:02}_{:016x}.bin: 0x{:016x} - 0x{:016x} (perms: 0x{:x})",
            i, *begin, *begin, *end, 0)?;
    }
    
    Ok(())
}
