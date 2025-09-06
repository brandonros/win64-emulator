/*
ReadFile function (fileapi.h)
07/22/2025
Reads data from the specified file or input/output (I/O) device. Reads occur at the position specified by the file pointer if supported by the device.

This function is designed for both synchronous and asynchronous operations. For a similar function designed solely for asynchronous operation, see ReadFileEx.

Syntax
C++

Copy
BOOL ReadFile(
  [in]                HANDLE       hFile,
  [out]               LPVOID       lpBuffer,
  [in]                DWORD        nNumberOfBytesToRead,
  [out, optional]     LPDWORD      lpNumberOfBytesRead,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
Parameters
[in] hFile

A handle to the device (for example, a file, file stream, physical disk, volume, console buffer, tape drive, socket, communications resource, mailslot, or pipe).

The hFile parameter must have been created with read access. For more information, see Generic Access Rights and File Security and Access Rights.

For asynchronous read operations, hFile can be any handle that is opened with the FILE_FLAG_OVERLAPPED flag by the CreateFile function, or a socket handle returned by the socket or accept function.

[out] lpBuffer

A pointer to the buffer that receives the data read from a file or device.

This buffer must remain valid for the duration of the read operation. The caller must not use this buffer until the read operation is completed.

[in] nNumberOfBytesToRead

The maximum number of bytes to be read.

[out, optional] lpNumberOfBytesRead

A pointer to the variable that receives the number of bytes read when using a synchronous hFile parameter. ReadFile sets this value to zero before doing any work or error checking. Use NULL for this parameter if this is an asynchronous operation to avoid potentially erroneous results.

This parameter can be NULL only when the lpOverlapped parameter is not NULL.

Windows 7: This parameter can not be NULL.

For more information, see the Remarks section.

[in, out, optional] lpOverlapped

A pointer to an OVERLAPPED structure is required if the hFile parameter was opened with FILE_FLAG_OVERLAPPED, otherwise it can be NULL.

If hFile is opened with FILE_FLAG_OVERLAPPED, the lpOverlapped parameter must point to a valid and unique OVERLAPPED structure, otherwise the function can incorrectly report that the read operation is complete.

For an hFile that supports byte offsets, if you use this parameter you must specify a byte offset at which to start reading from the file or device. This offset is specified by setting the Offset and OffsetHigh members of the OVERLAPPED structure. For an hFile that does not support byte offsets, Offset and OffsetHigh are ignored.

For more information about different combinations of lpOverlapped and FILE_FLAG_OVERLAPPED, see the Remarks section and the Synchronization and File Position section.

Return value
If the function succeeds, the return value is nonzero (TRUE).

If the function fails, or is completing asynchronously, the return value is zero (FALSE). To get extended error information, call the GetLastError function.

 Note

 The GetLastError code ERROR_IO_PENDING is not a failure; it designates the read operation is pending completion asynchronously. For more information, see Remarks.

Remarks
The ReadFile function returns when one of the following conditions occur:

The number of bytes requested is read.
A write operation completes on the write end of the pipe.
An asynchronous handle is being used and the read is occurring asynchronously.
An error occurs.
The ReadFile function may fail with ERROR_INVALID_USER_BUFFER or ERROR_NOT_ENOUGH_MEMORY whenever there are too many outstanding asynchronous I/O requests.

To cancel all pending asynchronous I/O operations, use either:

CancelIo: This function only cancels operations issued by the calling thread for the specified file handle.
CancelIoEx: This function cancels all operations issued by the threads for the specified file handle.
Use CancelSynchronousIo to cancel pending synchronous I/O operations.

I/O operations that are canceled complete with the error ERROR_OPERATION_ABORTED.

The ReadFile function may fail with ERROR_NOT_ENOUGH_QUOTA, which means the calling process's buffer could not be page-locked. For additional information, see SetProcessWorkingSetSize.

If part of a file is locked by another process and the read operation overlaps the locked portion, this function fails.

Accessing the input buffer while a read operation is using the buffer may lead to corruption of the data read into that buffer. Applications must not read from, write to, reallocate, or free the input buffer that a read operation is using until the read operation completes. This can be particularly problematic when using an asynchronous file handle. Additional information regarding synchronous versus asynchronous file handles can be found in the Synchronization and File Position section and in the CreateFile reference topic.

Characters can be read from the console input buffer by using ReadFile with a handle to console input. The console mode determines the exact behavior of the ReadFile function. By default, the console mode is ENABLE_LINE_INPUT, which indicates that ReadFile should read until it reaches a carriage return. If you press Ctrl+C, the call succeeds, but GetLastError returns ERROR_OPERATION_ABORTED. For more information, see CreateFile.

When reading from a communications device, the behavior of ReadFile is determined by the current communication time-out as set and retrieved by using the SetCommTimeouts and GetCommTimeouts functions. Unpredictable results can occur if you fail to set the time-out values. For more information about communication time-outs, see COMMTIMEOUTS.

If ReadFile attempts to read from a mailslot that has a buffer that is too small, the function returns FALSE and GetLastError returns ERROR_INSUFFICIENT_BUFFER.

There are strict requirements for successfully working with files opened with CreateFile using the FILE_FLAG_NO_BUFFERING flag. For details see File Buffering.

If hFile was opened with FILE_FLAG_OVERLAPPED, the following conditions are in effect:

The lpOverlapped parameter must point to a valid and unique OVERLAPPED structure, otherwise the function can incorrectly report that the read operation is complete.
The lpNumberOfBytesRead parameter should be set to NULL. Use the GetOverlappedResult function to get the actual number of bytes read. If the hFile parameter is associated with an I/O completion port, you can also get the number of bytes read by calling the GetQueuedCompletionStatus function.
If a read operation on a file begins at or beyond the end of the file, then the read operation fails with the error ERROR_HANDLE_EOF. If a read operation on a file begins before the end of the file, but the read operation extends past the end of the file, then the read operation succeeds, and the number of bytes read is the number of bytes that were read before the end of file was reached.

Synchronization and File Position
If hFile is opened with FILE_FLAG_OVERLAPPED, it is an asynchronous file handle; otherwise it is synchronous. The rules for using the OVERLAPPED structure are slightly different for each, as previously noted.

 Note

 If a file or device is opened for asynchronous I/O, subsequent calls to functions such as ReadFile using that handle generally return immediately, but can also behave synchronously with respect to blocked execution. For more information see Asynchronous disk I/O appears as synchronous on Windows.

Considerations for working with asynchronous file handles:

ReadFile may return before the read operation is complete. In this scenario, ReadFile returns FALSE and the GetLastError function returns ERROR_IO_PENDING, which allows the calling process to continue while the system completes the read operation.
The lpOverlapped parameter must not be NULL and should be used with the following facts in mind:
Although the event specified in the OVERLAPPED structure is set and reset automatically by the system, the offset that is specified in the OVERLAPPED structure is not automatically updated.
ReadFile resets the event to a nonsignaled state when it begins the I/O operation.
The event specified in the OVERLAPPED structure is set to a signaled state when the read operation is complete; until that time, the read operation is considered pending.
Because the read operation starts at the offset that is specified in the OVERLAPPED structure, and ReadFile may return before the system-level read operation is complete (read pending), neither the offset nor any other part of the structure should be modified, freed, or reused by the application until the event is signaled (that is, the read completes).
Considerations for working with synchronous file handles:

If lpOverlapped is NULL, the read operation starts at the current file position and ReadFile does not return until the operation is complete, and the system updates the file pointer before ReadFile returns.
If lpOverlapped is not NULL, the read operation starts at the offset that is specified in the OVERLAPPED structure and ReadFile does not return until the read operation is complete. The system updates the OVERLAPPED offset and the file pointer before ReadFile returns.
For more information, see CreateFile and Synchronous and Asynchronous I/O.

Pipes
If an anonymous pipe is being used and the write handle has been closed, when ReadFile attempts to read using the pipe's corresponding read handle, the function returns FALSE and GetLastError returns ERROR_BROKEN_PIPE.

If a named pipe is being read in message mode and the next message is longer than the nNumberOfBytesToRead parameter specifies, ReadFile returns FALSE and GetLastError returns ERROR_MORE_DATA. The remainder of the message can be read by a subsequent call to the ReadFile or PeekNamedPipe function.

If the lpNumberOfBytesRead parameter is zero when ReadFile returns TRUE on a pipe, the other end of the pipe called the WriteFile function with nNumberOfBytesToWrite set to zero.

For more information about pipes, see Pipes.

Transacted Operations
If there is a transaction bound to the file handle, then the function returns data from the transacted view of the file. A transacted read handle is guaranteed to show the same view of a file for the duration of the handle. For more information, see About Transactional NTFS.

In Windows 8 and Windows Server 2012, this function is supported by the following technologies.
*/

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
    // Windows standard handles (as returned by GetStdHandle):
    const STD_INPUT_HANDLE: u64 = 0xFFFFFFFFFFFFFFF6; // (DWORD)-10
    const STD_OUTPUT_HANDLE: u64 = 0xFFFFFFFFFFFFFFF5; // (DWORD)-11
    const STD_ERROR_HANDLE: u64 = 0xFFFFFFFFFFFFFFF4; // (DWORD)-12
    
    let is_std_handle = h_file == STD_INPUT_HANDLE || 
                       h_file == STD_OUTPUT_HANDLE || 
                       h_file == STD_ERROR_HANDLE;
    
    // Panic on complex paths as requested
    if lp_overlapped != 0 {
        panic!("ReadFile: Overlapped I/O not supported!");
    }
    
    // For synchronous operations (lpOverlapped is NULL), lpNumberOfBytesRead cannot be NULL
    if lp_overlapped == 0 && lp_number_of_bytes_read == 0 {
        log::error!("[ReadFile] lpNumberOfBytesRead cannot be NULL for synchronous operations");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    if n_number_of_bytes_to_read == 0 {
        panic!("ReadFile: Zero-byte reads not supported!");
    }
    
    if lp_buffer == 0 {
        panic!("ReadFile: NULL buffer not supported!");
    }
    
    if is_std_handle {
        // Simple case: handle standard input/output/error
        match h_file {
            STD_INPUT_HANDLE => {
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
            STD_OUTPUT_HANDLE | STD_ERROR_HANDLE => {
                // Attempting to read from stdout/stderr - this is unusual but not necessarily an error
                log::warn!("[ReadFile] Attempting to read from stdout/stderr handle: 0x{:x}", h_file);
                
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
                log::warn!("[ReadFile] Handle 0x{:x} not found in VFS ERROR_INVALID_HANDLE", h_file);
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