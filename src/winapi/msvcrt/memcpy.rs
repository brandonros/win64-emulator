use unicorn_engine::{Unicorn, RegisterX86};

/*
memcpy function (string.h)
Copies bytes between buffers.

Syntax
C

void *memcpy(
   void *dest,
   const void *src,
   size_t count
);

Parameters
dest
New buffer.

src
Buffer to copy from.

count
Number of bytes to copy.

Return value
The value of dest.

Remarks
memcpy copies count bytes from src to dest. If the source and destination overlap, 
the behavior of memcpy is undefined. Use memmove to handle overlapping regions.

Make sure that the destination buffer is at least as large as the source buffer.
*/

pub fn memcpy(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void *memcpy(
    //   void *dest,       // RCX
    //   const void *src,  // RDX
    //   size_t count      // R8
    // )
    
    let dest = emu.reg_read(RegisterX86::RCX)?;
    let src = emu.reg_read(RegisterX86::RDX)?;
    let count = emu.reg_read(RegisterX86::R8)?;
    
    log::info!("[memcpy] dest: 0x{:x}", dest);
    log::info!("[memcpy] src: 0x{:x}", src);
    log::info!("[memcpy] count: {} bytes", count);
    
    // Check for NULL pointers
    if dest == 0 {
        log::error!("[memcpy] NULL destination pointer");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }
    
    if src == 0 {
        log::error!("[memcpy] NULL source pointer");
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }
    
    // Check for zero count - valid operation but nothing to copy
    if count == 0 {
        log::info!("[memcpy] Zero bytes to copy");
        emu.reg_write(RegisterX86::RAX, dest)?;
        return Ok(());
    }
    
    // Read from source
    let mut buffer = vec![0u8; count as usize];
    match emu.mem_read(src, &mut buffer) {
        Ok(_) => {
            log::info!("[memcpy] Successfully read {} bytes from source", count);
        }
        Err(e) => {
            log::error!("[memcpy] Failed to read from source: {:?}", e);
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
    }
    
    // Write to destination
    match emu.mem_write(dest, &buffer) {
        Ok(_) => {
            log::info!("[memcpy] Successfully copied {} bytes to destination", count);
        }
        Err(e) => {
            log::error!("[memcpy] Failed to write to destination: {:?}", e);
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
    }
    
    // Log a sample of the copied data (first 32 bytes or less)
    let sample_size = std::cmp::min(32, count as usize);
    let sample: Vec<String> = buffer[..sample_size]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    log::info!("[memcpy] First {} bytes: {}", sample_size, sample.join(" "));
    
    // Check for potential overlap (warning only, still perform the copy)
    if src < dest && src + count > dest {
        log::warn!("[memcpy] Source and destination regions overlap - behavior undefined!");
        log::warn!("[memcpy] Consider using memmove for overlapping regions");
    } else if dest < src && dest + count > src {
        log::warn!("[memcpy] Source and destination regions overlap - behavior undefined!");
        log::warn!("[memcpy] Consider using memmove for overlapping regions");
    }
    
    // Return the destination pointer
    emu.reg_write(RegisterX86::RAX, dest)?;
    
    log::info!("[memcpy] Operation completed successfully");
    
    Ok(())
}