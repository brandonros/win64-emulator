use unicorn_engine::{Unicorn, RegisterX86};

/*
ZwSetInformationFile function (wdm.h)
01/13/2023
The ZwSetInformationFile routine changes various kinds of information about a file object.

Syntax
C++

Copy
NTSYSAPI NTSTATUS ZwSetInformationFile(
  [in]  HANDLE                 FileHandle,
  [out] PIO_STATUS_BLOCK       IoStatusBlock,
  [in]  PVOID                  FileInformation,
  [in]  ULONG                  Length,
  [in]  FILE_INFORMATION_CLASS FileInformationClass
);
Parameters
[in] FileHandle

Handle to the file object. This handle is created by a successful call to ZwCreateFile or ZwOpenFile.

[out] IoStatusBlock

Pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the requested operation. The Information member receives the number of bytes set on the file.

[in] FileInformation

Pointer to a buffer that contains the information to set for the file. The particular structure in this buffer is determined by the FileInformationClass parameter. For example, if the FileInformationClass parameter is set to the FileDispositionInformationEx constant, this parameter should be a pointer to a FILE_DISPOSITION_INFORMATION_EX structure.

[in] Length

The size, in bytes, of the FileInformation buffer.

[in] FileInformationClass

The type of information, supplied in the buffer pointed to by FileInformation, to set for the file. Device and intermediate drivers can specify any of the following FILE_INFORMATION_CLASS values.

FileInformationClass Value	Meaning
FileBasicInformation	Change the information that is supplied in a FILE_BASIC_INFORMATION structure. The caller must have opened the file with the FILE_WRITE_ATTRIBUTES flag set in the DesiredAccess parameter.
FileDispositionInformation	Request to delete the file when it is closed or cancel a previously requested deletion. The choice whether to delete or cancel is supplied in a FILE_DISPOSITION_INFORMATION structure. The caller must have opened the file with the DELETE flag set in the DesiredAccess parameter.
FileDispositionInformationEx	Request to delete the file or cancel a previously requested deletion. The choice whether to delete or cancel, as well as settings for when and how the deletion should be performed, are supplied in a FILE_DISPOSITION_INFORMATION_EX structure. The caller must have opened the file with the DELETE** flag set in the DesiredAccess parameter.
FileEndOfFileInformation	Change the current end-of-file information, supplied in a FILE_END_OF_FILE_INFORMATION structure. The operation can either truncate or extend the file. The caller must have opened the file with the FILE_WRITE_DATA flag set in the DesiredAccess parameter.
FileIoPriorityHintInformation	Change the current default IRP priority hint for the file handle. The new value is supplied in a FILE_IO_PRIORITY_HINT_INFORMATION structure. This structure must be 8-byte aligned.
FileLinkInformation	Create a hard link to an existing file, which is specified in a FILE_LINK_INFORMATION structure. Not all file systems support hard links; for example NTFS does while FAT does not.
FilePositionInformation	Change the current file information, which is stored in a FILE_POSITION_INFORMATION structure.
FileRenameInformation	Change the current file name, which is supplied in a FILE_RENAME_INFORMATION structure. The caller must have DELETE access to the file.
FileShortNameInformation	Change the current short file name, which is supplied in a FILE_NAME_INFORMATION structure. The file must be on an NTFS volume, and the caller must have opened the file with the DesiredAccess DELETE flag set in the DesiredAccess parameter.
FileIoCompletionNotificationInformation	Change the file IO completion notification flags. Supports the same flags as SetFileCompletionNotificationModes.
FileValidDataLengthInformation	Change the current valid data length for the file, which is supplied in a FILE_VALID_DATA_LENGTH_INFORMATION structure. The file must be on an NTFS volume, and the caller must have opened the file with the FILE_WRITE_DATA flag set in the DesiredAccess parameter. Non-administrators and remote users must have the SeManageVolumePrivilege privilege.
FileReplaceCompletionInformation	Change or remove the I/O completion port for the specified file handle. The caller supplies a pointer to a FILE_COMPLETION_INFORMATION structure that specifies a port handle and a completion key. If the port handle is non-NULL, this handle specifies a new I/O completion port to associate with the file handle. To remove the I/O completion port associated with the file handle, set the port handle in the structure to NULL. To get a port handle, a user-mode caller can call the CreateIoCompletionPort function.
Return value
ZwSetInformationFile returns STATUS_SUCCESS or an appropriate error status.

Remarks
ZwSetInformationFile changes information about a file. It ignores any member of a FILE_XXX_INFORMATION structure that is not supported by a particular device or file system.

If you set FileInformationClass to FileDispositionInformation, you can subsequently pass FileHandle to ZwClose but not to any other ZwXxxFile routine. Because FileDispositionInformation causes the file to be marked for deletion, it is a programming error to attempt any subsequent operation on the handle other than closing it.

If you set FileInformationClass to FilePositionInformation, and the preceding call to ZwCreateFile included the FILE_NO_INTERMEDIATE_BUFFERING flag in the CreateOptions parameter, certain restrictions on the CurrentByteOffset member of the FILE_POSITION_INFORMATION structure are enforced. For more information, see ZwCreateFile.

If you set FileInformationClass to FileEndOfFileInformation, and the EndOfFile member of FILE_END_OF_FILE_INFORMATION specifies an offset beyond the current end-of-file mark, ZwSetInformationFile extends the file and pads the extension with zeros.

For more information about working with files, see Using Files in a Driver.

Callers of ZwSetInformationFile must be running at IRQL = PASSIVE_LEVEL and with special kernel APCs enabled.

If the call to this function occurs in user mode, you should use the name "NtSetInformationFile" instead of "ZwSetInformationFile".

For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine can behave differently in the way that they handle and interpret input parameters. For more information about the relationship between the NtXxx and ZwXxx versions of a routine, see Using Nt and Zw Versions of the Native System Services Routines.


*/

pub fn ZwSetInformationFile(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // NTSTATUS ZwSetInformationFile(
    //   [in]  HANDLE                 FileHandle,           // RCX
    //   [out] PIO_STATUS_BLOCK       IoStatusBlock,        // RDX
    //   [in]  PVOID                  FileInformation,      // R8
    //   [in]  ULONG                  Length,               // R9
    //   [in]  FILE_INFORMATION_CLASS FileInformationClass  // [RSP+0x28]
    // )
    
    let file_handle = emu.reg_read(RegisterX86::RCX)?;
    let io_status_block = emu.reg_read(RegisterX86::RDX)?;
    let file_information = emu.reg_read(RegisterX86::R8)?;
    let length = emu.reg_read(RegisterX86::R9)? as u32;
    
    // Read FileInformationClass from stack
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut class_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x28, &mut class_bytes)?;
    let file_information_class = u32::from_le_bytes(class_bytes);
    
    log::info!("[ZwSetInformationFile] FileHandle: 0x{:x}", file_handle);
    log::info!("[ZwSetInformationFile] IoStatusBlock: 0x{:x}", io_status_block);
    log::info!("[ZwSetInformationFile] FileInformation: 0x{:x}", file_information);
    log::info!("[ZwSetInformationFile] Length: {}", length);
    log::info!("[ZwSetInformationFile] FileInformationClass: {}", file_information_class);
    
    // NTSTATUS constants
    const STATUS_SUCCESS: u32 = 0x00000000;
    const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
    
    // Basic validation
    if file_handle == 0 || io_status_block == 0 {
        log::error!("[ZwSetInformationFile] Invalid handle or IoStatusBlock");
        emu.reg_write(RegisterX86::RAX, STATUS_INVALID_PARAMETER as u64)?;
        return Ok(());
    }
    
    // Set up IO_STATUS_BLOCK (8 bytes Status + 8 bytes Information)
    let status = STATUS_SUCCESS;
    let information = length as u64; // Bytes processed
    
    emu.mem_write(io_status_block, &status.to_le_bytes())?;
    emu.mem_write(io_status_block + 8, &information.to_le_bytes())?;
    
    log::info!("[ZwSetInformationFile] Mock operation completed successfully");
    log::warn!("[ZwSetInformationFile] Mock implementation - no actual file operation performed");
    
    // Return STATUS_SUCCESS
    emu.reg_write(RegisterX86::RAX, STATUS_SUCCESS as u64)?;
    
    Ok(())
}