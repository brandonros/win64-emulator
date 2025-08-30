use unicorn_engine::{Unicorn, RegisterX86};

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

pub fn ZwReadFile(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
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
    
    let file_handle = emu.reg_read(RegisterX86::RCX)?;
    let event = emu.reg_read(RegisterX86::RDX)?;
    let apc_routine = emu.reg_read(RegisterX86::R8)?;
    let apc_context = emu.reg_read(RegisterX86::R9)?;
    
    // Read remaining parameters from stack
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    
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
        emu.reg_write(RegisterX86::RAX, STATUS_INVALID_PARAMETER as u64)?;
        return Ok(());
    }
    
    // Mock read operation - fill buffer with pattern data
    let bytes_to_read = std::cmp::min(length as usize, 256); // Cap at 256 bytes for mock
    let mock_data: Vec<u8> = (0..bytes_to_read).map(|i| (i % 256) as u8).collect();
    
    // Write mock data to buffer
    emu.mem_write(buffer, &mock_data)?;
    
    // Set up IO_STATUS_BLOCK (8 bytes Status + 8 bytes Information)
    let status = STATUS_SUCCESS;
    let bytes_read = bytes_to_read as u64;
    
    emu.mem_write(io_status_block, &status.to_le_bytes())?;
    emu.mem_write(io_status_block + 8, &bytes_read.to_le_bytes())?;
    
    log::info!("[ZwReadFile] Mock read {} bytes", bytes_read);
    log::warn!("[ZwReadFile] Mock implementation - returned pattern data");
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, STATUS_SUCCESS as u64)?;
    
    Ok(())
}