use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::vfs::VIRTUAL_FS;
use crate::winapi;

pub fn ReadFile(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL ReadFile(
    //   HANDLE hFile,
    //   LPVOID lpBuffer,
    //   DWORD nNumberOfBytesToRead,
    //   LPDWORD lpNumberOfBytesRead,
    //   LPOVERLAPPED lpOverlapped
    // )
    
    let h_file = emu.reg_read(RegisterX86::RCX)?;
    let lp_buffer = emu.reg_read(RegisterX86::RDX)?;
    let n_number_of_bytes_to_read = emu.reg_read(RegisterX86::R8)? as u32;
    let lp_number_of_bytes_read = emu.reg_read(RegisterX86::R9)?;
    
    // Get lpOverlapped from stack (5th parameter)
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let lp_overlapped_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let lp_overlapped = u64::from_le_bytes(lp_overlapped_bytes.try_into().unwrap());
    
    log::info!("[ReadFile] hFile: 0x{:x}, lpBuffer: 0x{:x}, nNumberOfBytesToRead: {}, lpNumberOfBytesRead: 0x{:x}, lpOverlapped: 0x{:x}",
              h_file, lp_buffer, n_number_of_bytes_to_read, lp_number_of_bytes_read, lp_overlapped);

    // Check for standard handles first
    let is_std_handle = h_file == 0x10 || h_file == 0x14 || h_file == 0x18;
    
    // Panic on complex paths as requested
    if lp_overlapped != 0 {
        panic!("ReadFile: Overlapped I/O not supported!");
    }
    
    if n_number_of_bytes_to_read == 0 {
        panic!("ReadFile: Zero-byte reads not supported!");
    }
    
    if lp_buffer == 0 {
        panic!("ReadFile: NULL buffer not supported!");
    }
    
    if is_std_handle {
        // Simple case: handle standard input/output/error
        // Standard handles from GetStdHandle: stdin=0x10, stdout=0x14, stderr=0x18
        match h_file {
            0x10 => {
                // Reading from stdin - simulate some input or EOF
                log::info!("[ReadFile] Reading from stdin");
                
                // For simulation purposes, we'll return EOF (0 bytes read)
                // In a real implementation, you might want to provide actual input data
                let bytes_read = 0u32;
                
                // Set number of bytes read if pointer provided
                if lp_number_of_bytes_read != 0 {
                    emu.mem_write(lp_number_of_bytes_read, &bytes_read.to_le_bytes())?;
                }
                
                // Return TRUE (success) - EOF is still a successful read
                emu.reg_write(RegisterX86::RAX, 1)?;
                
                log::info!("[ReadFile] EOF reached on stdin, {} bytes read", bytes_read);
            },
            0x14 | 0x18 => {
                // Attempting to read from stdout/stderr - this is unusual but not necessarily an error
                log::warn!("[ReadFile] Attempting to read from stdout/stderr handle");
                
                // Set error for invalid operation
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION)?;
                emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
            },
            _ => unreachable!()
        }
    } else {
        // Check VFS for registered file handles
        let (filename, file_data) = {
            let vfs = VIRTUAL_FS.read().unwrap();
            if let Some(file_info) = vfs.get_file_info(h_file) {
                let filename = file_info.filename.clone();
                log::info!("[ReadFile] Reading from file: '{}'", filename);
                
                // Try to read actual file from mock_files
                let file_data = match vfs.read_mock_file(&filename) {
                    Ok(data) => {
                        log::info!("[ReadFile] Found mock file data for '{}'", filename);
                        data
                    },
                    Err(_) => {
                        log::info!("[ReadFile] No mock file found for '{}', using pattern data", filename);
                        // Generate pattern data as fallback
                        let bytes_to_read = std::cmp::min(n_number_of_bytes_to_read as usize, 256);
                        (0..bytes_to_read).map(|i| (i % 256) as u8).collect()
                    }
                };
                (Some(filename), file_data)
            } else {
                log::warn!("[ReadFile] Handle 0x{:x} not found in VFS", h_file);
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
                emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
                return Ok(());
            }
        };
        
        // Get current file position
        let position = {
            let vfs = VIRTUAL_FS.read().unwrap();
            vfs.get_file_info(h_file).map(|fi| fi.position).unwrap_or(0)
        };
        
        // Read data from the current position
        let bytes_to_read = std::cmp::min(
            n_number_of_bytes_to_read as usize, 
            file_data.len().saturating_sub(position as usize)
        );
        let data_slice = &file_data[position as usize..position as usize + bytes_to_read];
        
        // Write data to buffer
        emu.mem_write(lp_buffer, data_slice)?;
        
        // Update file position in VFS
        {
            let mut vfs = VIRTUAL_FS.write().unwrap();
            vfs.update_position(h_file, position + bytes_to_read as u64);
        }
        
        // Set number of bytes read if pointer provided
        if lp_number_of_bytes_read != 0 {
            emu.mem_write(lp_number_of_bytes_read, &(bytes_to_read as u32).to_le_bytes())?;
        }
        
        // Return TRUE (success)
        emu.reg_write(RegisterX86::RAX, 1)?;
        
        if let Some(filename) = filename {
            log::info!("[ReadFile] Read {} bytes from '{}' at offset {}", bytes_to_read, filename, position);
        } else {
            log::info!("[ReadFile] Read {} bytes from handle 0x{:x}", bytes_to_read, h_file);
        }
    }
    
    Ok(())
}