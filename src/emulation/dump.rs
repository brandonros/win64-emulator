use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use unicorn_engine::Unicorn;

use crate::loader_error::LoaderError;

pub fn dump_memory(
    emu: &mut Unicorn<'static, ()>,
    output_dir: &Path,
) -> Result<(), LoaderError> {
    // Create output directory
    std::fs::create_dir_all(output_dir)
        .map_err(|e| LoaderError::IoError(e))?;
    
    let regions = emu.mem_regions()
        .map_err(|e| LoaderError::UnicornError(e))?;
    
    log::info!("📦 Dumping {} memory regions to separate files", regions.len());
    
    for (i, region) in regions.iter().enumerate() {
        let size = (region.end - region.begin + 1) as usize;
        let mut buffer = vec![0u8; size];
        
        if let Ok(_) = emu.mem_read(region.begin, &mut buffer) {
            let filename = format!("region_{:02}_{:016x}.bin", i, region.begin);
            let filepath = output_dir.join(&filename);
            
            File::create(&filepath)?
                .write_all(&buffer)?;
            
            log::info!("  Saved region {} (0x{:016x} - 0x{:016x}) to {}", 
                i, region.begin, region.end, filename);
        }
    }
    
    // Write mapping info
    let info_path = output_dir.join("regions.txt");
    let mut info = File::create(&info_path)?;
    
    for (i, region) in regions.iter().enumerate() {
        writeln!(info, "region_{:02}_{:016x}.bin: 0x{:016x} - 0x{:016x} (perms: 0x{:x})",
            i, region.begin, region.begin, region.end, region.perms)?;
    }
    
    Ok(())
}
