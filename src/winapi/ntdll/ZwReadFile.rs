use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::{vfs::VIRTUAL_FS, memory};
use windows_sys::Win32::{System::IO::IO_STATUS_BLOCK, Foundation::NTSTATUS};

/*
ZwReadFile function (wdm.h)
01/13/2023
The ZwReadFile routine reads data from an open file.

Syntax
C++

Copy
NTSYSAPI NTSTATUS ZwReadFile(
  [in]           HANDLE           FileHandle,
  [in, optional] HANDLE           Event,
  [in, optional] PIO_APC_ROUTINE  ApcRoutine,
  [in, optional] PVOID            ApcContext,
  [out]          PIO_STATUS_BLOCK IoStatusBlock,
  [out]          PVOID            Buffer,
  [in]           ULONG            Length,
  [in, optional] PLARGE_INTEGER   ByteOffset,
  [in, optional] PULONG           Key
);
Parameters
[in] FileHandle

Handle to the file object. This handle is created by a successful call to ZwCreateFile or ZwOpenFile.

[in, optional] Event

Optionally, a handle to an event object to set to the signaled state after the read operation completes. Device and intermediate drivers should set this parameter to NULL.

[in, optional] ApcRoutine

This parameter is reserved. Device and intermediate drivers should set this pointer to NULL.

[in, optional] ApcContext

This parameter is reserved. Device and intermediate drivers should set this pointer to NULL.

[out] IoStatusBlock

Pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the requested read operation. The Information member receives the number of bytes actually read from the file.

[out] Buffer

Pointer to a caller-allocated buffer that receives the data read from the file.

[in] Length

The size, in bytes, of the buffer pointed to by Buffer.

[in, optional] ByteOffset

Pointer to a variable that specifies the starting byte offset in the file where the read operation will begin. If an attempt is made to read beyond the end of the file, ZwReadFile returns an error.

If the call to ZwCreateFile set either of the CreateOptions flags FILE_SYNCHRONOUS_IO_ALERT or FILE_SYNCHRONOUS_IO_NONALERT, the I/O Manager maintains the current file position. If so, the caller of ZwReadFile can specify that the current file position offset be used instead of an explicit ByteOffset value. This specification can be made by using one of the following methods:

Specify a pointer to a LARGE_INTEGER value with the HighPart member set to -1 and the LowPart member set to the system-defined value FILE_USE_FILE_POINTER_POSITION.

Pass a NULL pointer for ByteOffset.

ZwReadFile updates the current file position by adding the number of bytes read when it completes the read operation, if it is using the current file position maintained by the I/O Manager.

Even when the I/O Manager is maintaining the current file position, the caller can reset this position by passing an explicit ByteOffset value to ZwReadFile. Doing this automatically changes the current file position to that ByteOffset value, performs the read operation, and then updates the position according to the number of bytes actually read. This technique gives the caller atomic seek-and-read service.

[in, optional] Key

Device and intermediate drivers should set this pointer to NULL.

Return value
ZwReadFile returns either STATUS_SUCCESS or the appropriate NTSTATUS error code.

Remarks
Callers of ZwReadFile must have already called ZwCreateFile with the FILE_READ_DATA or GENERIC_READ value set in the DesiredAccess parameter.

If the preceding call to ZwCreateFile set the FILE_NO_INTERMEDIATE_BUFFERING flag in the CreateOptions parameter to ZwCreateFile, the Length and ByteOffset parameters to ZwReadFile must be multiples of the sector size. For more information, see ZwCreateFile.

ZwReadFile begins reading from the given ByteOffset or the current file position into the given Buffer. It terminates the read operation under one of the following conditions:

The buffer is full because the number of bytes specified by the Length parameter has been read. Therefore, no more data can be placed into the buffer without an overflow.

The end of file is reached during the read operation, so there is no more data in the file to be transferred into the buffer.

If the caller opened the file with the SYNCHRONIZE flag set in DesiredAccess, the calling thread can synchronize to the completion of the read operation by waiting on the file handle, FileHandle. The handle is signaled each time that an I/O operation that was issued on the handle completes. However, the caller must not wait on a handle that was opened for synchronous file access (FILE_SYNCHRONOUS_IO_NONALERT or FILE_SYNCHRONOUS_IO_ALERT). In this case, ZwReadFile waits on behalf of the caller and does not return until the read operation is complete. The caller can safely wait on the file handle only if all three of the following conditions are met:

The handle was opened for asynchronous access (that is, neither FILE_SYNCHRONOUS_IO_XXX flag was specified).

The handle is being used for only one I/O operation at a time.

ZwReadFile returned STATUS_PENDING.

A driver should call ZwReadFile in the context of the system process if any of the following conditions exist:

The driver created the file handle that it passes to ZwReadFile.

ZwReadFile will notify the driver of I/O completion by means of an event that the driver created.

ZwReadFile will notify the driver of I/O completion by means of an APC callback routine that the driver passes to ZwReadFile.

File and event handles are valid only in the process context where the handles are created. Therefore, to avoid security holes, the driver should create any file or event handle that it passes to ZwReadFile in the context of the system process rather than the context of the process that the driver is in.

Likewise, ZwReadFile should be called in the context of the system process if it notifies the driver of I/O completion by means of an APC, because APCs are always fired in the context of the thread that issues the I/O request. If the driver calls ZwReadFile in the context of a process other than the system one, the APC could be delayed indefinitely, or it might not fire at all.

For more information about working with files, see Using Files in a Driver.

Callers of ZwReadFile must be running at IRQL = PASSIVE_LEVEL and with special kernel APCs enabled.

If the call to this function occurs in user mode, you should use the name "NtReadFile" instead of "ZwReadFile".
*/

/*
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut c_void,
}
*/
pub fn ZwReadFile(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // NTSTATUS ZwReadFile(
    //   [in]           HANDLE           FileHandle,     // RCX
    //   [in, optional] HANDLE           Event,          // RDX
    //   [in, optional] PIO_APC_ROUTINE  ApcRoutine,     // R8
    //   [in, optional] PVOID            ApcContext,     // R9
    //   [out]          PIO_STATUS_BLOCK IoStatusBlock,  // [RSP+0x28]
    //   [out]          PVOID            Buffer,         // [RSP+0x30]
    //   [in]           ULONG            Length,         // [RSP+0x38]
    //   [in, optional] PLARGE_INTEGER   ByteOffset,     // [RSP+0x40]
    //   [in, optional] PULONG           Key             // [RSP+0x48]
    // )
    
    let file_handle = emu.reg_read(X86Register::RCX)?;
    let event = emu.reg_read(X86Register::RDX)?;
    let apc_routine = emu.reg_read(X86Register::R8)?;
    let apc_context = emu.reg_read(X86Register::R9)?;
    
    // Read remaining parameters from stack
    let rsp = emu.reg_read(X86Register::RSP)?;
    
    let mut io_status_block_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x28, &mut io_status_block_bytes)?;
    let io_status_block = u64::from_le_bytes(io_status_block_bytes);
    
    let mut buffer_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x30, &mut buffer_bytes)?;
    let buffer = u64::from_le_bytes(buffer_bytes);
    
    let mut length_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x38, &mut length_bytes)?;
    let length = u32::from_le_bytes(length_bytes);
    
    log::info!("[ZwReadFile] FileHandle: 0x{:x}", file_handle);
    log::info!("[ZwReadFile] Event: 0x{:x}", event);
    log::info!("[ZwReadFile] ApcRoutine: 0x{:x}", apc_routine);
    log::info!("[ZwReadFile] ApcContext: 0x{:x}", apc_context);
    log::info!("[ZwReadFile] IoStatusBlock: 0x{:x}", io_status_block);
    log::info!("[ZwReadFile] Buffer: 0x{:x}", buffer);
    log::info!("[ZwReadFile] Length: {}", length);
    
    // NTSTATUS constants
    const STATUS_SUCCESS: u32 = 0x00000000;
    const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
    const STATUS_END_OF_FILE: u32 = 0xC0000011;
    
    // Basic validation
    if file_handle == 0 || io_status_block == 0 || buffer == 0 {
        log::error!("[ZwReadFile] Invalid parameters");
        emu.reg_write(X86Register::RAX, STATUS_INVALID_PARAMETER as u64)?;
        return Ok(());
    }
    
    // Check if handle is registered in VFS
    let (filename, file_data) = {
        let vfs = VIRTUAL_FS.read().unwrap();
        if let Some(file_info) = vfs.get_file_info(file_handle) {
            let filename = file_info.filename.clone();
            log::info!("[ZwReadFile] [VFS] Reading from file: '{}'", filename);
            
            // Try to read actual file from mock_files
            let file_data = match vfs.read_mock_file(&filename) {
                Ok(data) => {
                    log::info!("[ZwReadFile] [VFS] Found mock file data for '{}'", filename);
                    data
                },
                Err(_) => {
                    log::info!("[ZwReadFile] [VFS] No mock file found for '{}', using pattern data", filename);
                    // Generate pattern data as fallback
                    let bytes_to_read = std::cmp::min(length as usize, 256);
                    (0..bytes_to_read).map(|i| (i % 256) as u8).collect()
                }
            };
            (Some(filename), file_data)
        } else {
            log::warn!("[ZwReadFile] [VFS] Handle 0x{:x} not found in VFS, using pattern data", file_handle);
            // Generate pattern data for unknown handles
            let bytes_to_read = std::cmp::min(length as usize, 256);
            let data = (0..bytes_to_read).map(|i| (i % 256) as u8).collect();
            (None, data)
        }
    };
    
    // Get current file position
    let position = {
        let vfs = VIRTUAL_FS.read().unwrap();
        vfs.get_file_info(file_handle).map(|fi| fi.position).unwrap_or(0)
    };
    
    // Handle ByteOffset parameter
    // First, read the ByteOffset pointer from the stack
    let mut byte_offset_ptr_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x40, &mut byte_offset_ptr_bytes)?;
    let byte_offset_ptr = u64::from_le_bytes(byte_offset_ptr_bytes);
    
    let actual_offset = if byte_offset_ptr == 0 {
        // NULL pointer means use current file position
        log::debug!("[ZwReadFile] NULL ByteOffset, using current file position: {}", position);
        position
    } else {
        // Read the actual LARGE_INTEGER value
        let mut offset_bytes = [0u8; 8];
        if emu.mem_read(byte_offset_ptr, &mut offset_bytes).is_ok() {
            let offset = i64::from_le_bytes(offset_bytes);
            
            // Check for FILE_USE_FILE_POINTER_POSITION special value
            // This is -1 as a LARGE_INTEGER (0xFFFFFFFFFFFFFFFE)
            const FILE_USE_FILE_POINTER_POSITION: i64 = 0xFFFFFFFFFFFFFFFE_u64 as i64;
            
            if offset == FILE_USE_FILE_POINTER_POSITION {
                log::debug!("[ZwReadFile] FILE_USE_FILE_POINTER_POSITION specified, using position: {}", position);
                position
            } else if offset < 0 {
                // Negative offsets (other than the special value) are invalid
                log::error!("[ZwReadFile] Invalid negative offset: {}", offset);
                emu.reg_write(X86Register::RAX, STATUS_INVALID_PARAMETER as u64)?;
                return Ok(());
            } else {
                log::debug!("[ZwReadFile] Using explicit ByteOffset: {}", offset);
                offset as u64
            }
        } else {
            log::error!("[ZwReadFile] Failed to read LARGE_INTEGER at ByteOffset pointer 0x{:x}", byte_offset_ptr);
            emu.reg_write(X86Register::RAX, STATUS_INVALID_PARAMETER as u64)?;
            return Ok(());
        }
    };
    
    // Read data from the calculated offset
    let bytes_to_read = std::cmp::min(length as usize, file_data.len().saturating_sub(actual_offset as usize));
    
    // Log file size for debugging EOF situations
    if bytes_to_read == 0 && length > 0 {
        log::info!("[ZwReadFile] [VFS] EOF reached - file size: {}, offset: {}, requested: {}", 
            file_data.len(), actual_offset, length);
    } else {
        log::info!("[ZwReadFile] [VFS] Reading {} bytes from offset {} (requested: {} bytes, file size: {})", 
            bytes_to_read, actual_offset, length, file_data.len());
    }
    
    let data_slice = &file_data[actual_offset as usize..actual_offset as usize + bytes_to_read];
    
    // Write data to buffer
    emu.mem_write(buffer, data_slice)?;
    
    // Update file position in VFS
    {
        let mut vfs = VIRTUAL_FS.write().unwrap();
        vfs.update_position(file_handle, actual_offset + bytes_to_read as u64);
    }
    
    // Set up IO_STATUS_BLOCK using proper struct
    let status = if bytes_to_read == 0 && length > 0 {
        STATUS_END_OF_FILE
    } else {
        STATUS_SUCCESS
    };
    
    // Create and write IO_STATUS_BLOCK
    // IO_STATUS_BLOCK structure on x64:
    // - Union (8 bytes): Contains either Status (NTSTATUS, 4 bytes) or Pointer (PVOID, 8 bytes)
    // - Information (8 bytes): ULONG_PTR on x64
    // Total size: 16 bytes
    
    let status_value = status as i32; // NTSTATUS is i32
    let information_value = bytes_to_read as usize;
    
    // Write the union field (8 bytes total, Status in first 4 bytes)
    let mut union_bytes = [0u8; 8];
    union_bytes[0..4].copy_from_slice(&status_value.to_le_bytes());
    emu.mem_write(io_status_block, &union_bytes)?;
    
    // Write Information field (8 bytes on x64)
    emu.mem_write(io_status_block + 8, &information_value.to_le_bytes())?;
    
    log::debug!("[ZwReadFile] IO_STATUS_BLOCK @ 0x{:x}: Status=0x{:08x}, Information={} bytes", 
        io_status_block, status, information_value);
    
    if let Some(filename) = filename {
        log::info!("[ZwReadFile] [VFS] Read {} bytes from '{}' at offset {}", bytes_to_read, filename, actual_offset);
    } else {
        log::info!("[ZwReadFile] [VFS] Read {} bytes from handle 0x{:x}", bytes_to_read, file_handle);
    }
    
    // TODO: return STATUS_END_OF_FILE or always STATUS_SUCCESS?
    emu.reg_write(X86Register::RAX, STATUS_SUCCESS as u64)?;
    
    log::debug!("[ZwReadFile] Returning NTSTATUS: 0x{:08x}", status);
    
    Ok(())
}