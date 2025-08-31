/*
ZwQueryInformationFile function (wdm.h)
01/06/2023
The ZwQueryInformationFile routine returns various kinds of information about a file object.

Syntax
C++

Copy
NTSYSAPI NTSTATUS ZwQueryInformationFile(
  [in]  HANDLE                 FileHandle,
  [out] PIO_STATUS_BLOCK       IoStatusBlock,
  [out] PVOID                  FileInformation,
  [in]  ULONG                  Length,
  [in]  FILE_INFORMATION_CLASS FileInformationClass
);
Parameters
[in] FileHandle

Handle to a file object. The handle is created by a successful call to ZwCreateFile or ZwOpenFile.

[out] IoStatusBlock

Pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation. The Information member receives the number of bytes that this routine actually writes to the FileInformation buffer.

[out] FileInformation

Pointer to a caller-allocated buffer into which the routine writes the requested information about the file object. The FileInformationClass parameter specifies the type of information that the caller requests.

[in] Length

The size, in bytes, of the buffer pointed to by FileInformation.

[in] FileInformationClass

Specifies the type of information to be returned about the file, in the buffer that FileInformation points to. Device and intermediate drivers can specify any of the following FILE_INFORMATION_CLASS values.

FILE_INFORMATION_CLASS value	Type of information returned
FileBasicInformation (4)	A FILE_BASIC_INFORMATION structure. The caller must have opened the file with the FILE_READ_ATTRIBUTES flag specified in the DesiredAccess parameter.
FileStandardInformation (5)	A FILE_STANDARD_INFORMATION structure. The caller can query this information as long as the file is open, without any particular requirements for DesiredAccess.
FileInternalInformation (6)	A FILE_INTERNAL_INFORMATION structure. This structure specifies a 64-bit file ID that uniquely identifies a file in NTFS. On other file systems, this file ID is not guaranteed to be unique.
FileEaInformation (7)	A FILE_EA_INFORMATION structure. This structure specifies the size of the extended attributes block that is associated with the file.
FileAccessInformation (8)	A FILE_ACCESS_INFORMATION structure. This structure contains an access mask. For more information about access masks, see ACCESS_MASK.
FileNameInformation (9)	A FILE_NAME_INFORMATION structure. The structure can contain the file's full path or only a portion of it. The caller can query this information as long as the file is open, without any particular requirements for DesiredAccess. For more information about the file-name syntax, see the Remarks section later in this topic.
FilePositionInformation (14)	A FILE_POSITION_INFORMATION structure. The caller must have opened the file with the DesiredAccess FILE_READ_DATA or FILE_WRITE_DATA flag specified in the DesiredAccess parameter, and with the FILE_SYNCHRONOUS_IO_ALERT or FILE_SYNCHRONOUS_IO_NONALERT flag specified in the CreateOptions parameter.
FileModeInformation (16)	A FILE_MODE_INFORMATION structure. This structure contains a set of flags that specify the mode in which the file can be accessed. These flags are a subset of the options that can be specified in the CreateOptions parameter of the IoCreateFile routine.
FileAlignmentInformation (17)	A FILE_ALIGNMENT_INFORMATION structure. The caller can query this information as long as the file is open, without any particular requirements for DesiredAccess[**. This information is useful if the file was opened with the FILE_NO_INTERMEDIATE_BUFFERING flag specified in the CreateOptions parameter.
FileAllInformation (18)	A FILE_ALL_INFORMATION structure. By combining several file-information structures into a single structure, FILE_ALL_INFORMATION reduces the number of queries required to obtain information about a file.
FileNetworkOpenInformation (34)	A FILE_NETWORK_OPEN_INFORMATION structure. The caller must have opened the file with the FILE_READ_ATTRIBUTES flag specified in the DesiredAccess parameter.
FileAttributeTagInformation (35)	A FILE_ATTRIBUTE_TAG_INFORMATION structure. The caller must have opened the file with the FILE_READ_ATTRIBUTES flag specified in the DesiredAccess parameter.
FileIoPriorityHintInformation (43)	A FILE_IO_PRIORITY_HINT_INFORMATION structure. The caller must have opened the file with the FILE_READ_DATA flag specified in the DesiredAccess parameter.
FileIsRemoteDeviceInformation (51)	A FILE_IS_REMOTE_DEVICE_INFORMATION structure. The caller can query this information as long as the file is open, without any particular requirements for DesiredAccess.
FileKnownFolderInformation (76)	A FILE_KNOWN_FOLDER_INFORMATION structure. Available starting in Windows Server 2022.
Return value
ZwQueryInformationFile returns STATUS_SUCCESS or an appropriate NTSTATUS error code.

Remarks
ZwQueryInformationFile returns information about the specified file object. Note that it returns zero in any member of a FILE_XXX_INFORMATION structure that is not supported by a particular device or file system.

When FileInformationClass = FileNameInformation, the file name is returned in the FILE_NAME_INFORMATION structure. The precise syntax of the file name depends on a number of factors:

If you opened the file by submitting a full path to ZwCreateFile, ZwQueryInformationFile returns that full path.

If the ObjectAttributes->RootDirectory handle was opened by name in a call to ZwCreateFile, and subsequently the file was opened by ZwCreateFile relative to this root-directory handle, ZwQueryInformationFile returns the full path.

If the ObjectAttributes->RootDirectory handle was opened by file ID (using the FILE_OPEN_BY_FILE_ID flag) in a call to ZwCreateFile, and subsequently the file was opened by ZwCreateFile relative to this root-directory handle, ZwQueryInformationFile returns the relative path.

However, if the user has SeChangeNotifyPrivilege, ZwQueryInformationFile returns the full path in all cases.

If only the relative path is returned, the file name string will not begin with a backslash.

If the full path and file name are returned, the string will begin with a single backslash, regardless of its location. Thus the file C:\dir1\dir2\filename.ext will appear as \dir1\dir2\filename.ext, while the file \\server\share\dir1\dir2\filename.ext will appear as \server\share\dir1\dir2\filename.ext.

If ZwQueryInformationFile fails because of a buffer overflow, drivers that implement FileNameInformation should return as many WCHAR characters of the file name as will fit in the buffer and specify the full length that is required in the FileNameLength parameter of the FILE_NAME_INFORMATION structure. You should reissue the query by using the file name length so that you can retrieve the full file name. Drivers that do not follow this pattern might require a gradual increase in length until they retrieve the full file name. For more information about working with files, see Using Files in a Driver.

Callers of ZwQueryInformationFile must be running at IRQL = PASSIVE_LEVEL and with special kernel APCs enabled.

If the call to this function occurs in user mode, you should use the name "NtQueryInformationFile" instead of "ZwQueryInformationFile".

For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine can behave differently in the way that they handle and interpret input parameters. For more information about the relationship between the NtXxx**** and ZwXxx**** versions of a routine, see Using Nt and Zw Versions of the Native System Services Routines.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::vfs::VIRTUAL_FS;
use crate::emulation::memory;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ALIGNMENT_INFORMATION,
    FILE_BASIC_INFORMATION,
    FILE_INTERNAL_INFORMATION,
    FILE_MODE_INFORMATION,
    FILE_NAME_INFORMATION,
    FILE_POSITION_INFORMATION,
    FILE_STANDARD_INFORMATION,
    FILE_ACCESS_INFORMATION,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0};

// FILE_INFORMATION_CLASS enum values
const FILE_BASIC_INFORMATION_CLASS: u32 = 4;
const FILE_STANDARD_INFORMATION_CLASS: u32 = 5;
const FILE_INTERNAL_INFORMATION_CLASS: u32 = 6;
const FILE_EA_INFORMATION_CLASS: u32 = 7;
const FILE_ACCESS_INFORMATION_CLASS: u32 = 8;
const FILE_NAME_INFORMATION_CLASS: u32 = 9;
const FILE_POSITION_INFORMATION_CLASS: u32 = 14;
const FILE_MODE_INFORMATION_CLASS: u32 = 16;
const FILE_ALIGNMENT_INFORMATION_CLASS: u32 = 17;

// NTSTATUS codes
const STATUS_SUCCESS: u32 = 0x00000000;
const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC0000003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC0000004;
const STATUS_BUFFER_OVERFLOW: u32 = 0x80000005;

pub fn ZwQueryInformationFile(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // NTSTATUS ZwQueryInformationFile(
    //   HANDLE                 FileHandle,           // RCX
    //   PIO_STATUS_BLOCK       IoStatusBlock,        // RDX
    //   PVOID                  FileInformation,      // R8
    //   ULONG                  Length,               // R9
    //   FILE_INFORMATION_CLASS FileInformationClass  // Stack [RSP+0x28]
    // )
    
    let file_handle = emu.reg_read(RegisterX86::RCX)?;
    let io_status_block_ptr = emu.reg_read(RegisterX86::RDX)?;
    let file_info_ptr = emu.reg_read(RegisterX86::R8)?;
    let length = emu.reg_read(RegisterX86::R9)? as u32;
    
    // Read FileInformationClass from stack
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut info_class_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x28, &mut info_class_bytes)?;
    let info_class = u32::from_le_bytes(info_class_bytes);
    
    log::info!(
        "[ZwQueryInformationFile] Handle: 0x{:x}, InfoClass: {}, Buffer: 0x{:x}, Length: {}",
        file_handle, info_class, file_info_ptr, length
    );
    
    // Check if handle is valid in VFS
    let file_info = {
        let vfs = VIRTUAL_FS.read().unwrap();
        vfs.get_file_info(file_handle).cloned()
    };
    
    let (status, bytes_written) = if let Some(file_info) = file_info {
        match info_class {
            FILE_STANDARD_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_STANDARD_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileStandardInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    let info = FILE_STANDARD_INFORMATION {
                        AllocationSize: 4096,  // Mock: assume 4KB allocation
                        EndOfFile: 1024,      // Mock: 1KB file size
                        NumberOfLinks: 1,
                        DeletePending: false,
                        Directory: false,
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileStandardInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_BASIC_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_BASIC_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileBasicInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    // Mock timestamps (using Windows FILETIME epoch: Jan 1, 1601)
                    let info = FILE_BASIC_INFORMATION {
                        CreationTime: 132514704000000000,   // Mock: Jan 1, 2021
                        LastAccessTime: 132514704000000000,
                        LastWriteTime: 132514704000000000,
                        ChangeTime: 132514704000000000,
                        FileAttributes: 0x20,  // FILE_ATTRIBUTE_ARCHIVE
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileBasicInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_NAME_INFORMATION_CLASS => {
                // Convert filename to wide string
                let wide_name: Vec<u16> = file_info.filename.encode_utf16().collect();
                let name_bytes_len = (wide_name.len() * 2) as u32;
                let header_size = std::mem::size_of::<FILE_NAME_INFORMATION>() as u32;
                let required_size = header_size + name_bytes_len;
                
                if length < header_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileNameInformation header");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    // Write the header
                    let name_info = FILE_NAME_INFORMATION {
                        FileNameLength: name_bytes_len,
                        FileName: [0u16; 1], // Placeholder, actual name follows
                    };
                    memory::write_struct(emu, file_info_ptr, &name_info)?;
                    
                    // Write as much of the filename as will fit
                    let available_for_name = length.saturating_sub(header_size);
                    let bytes_to_write = std::cmp::min(name_bytes_len, available_for_name) as usize;
                    
                    if bytes_to_write > 0 {
                        let name_ptr = file_info_ptr + header_size as u64;
                        let name_bytes: Vec<u8> = wide_name.iter()
                            .take(bytes_to_write / 2)
                            .flat_map(|&w| w.to_le_bytes())
                            .collect();
                        emu.mem_write(name_ptr, &name_bytes)?;
                    }
                    
                    log::info!("[ZwQueryInformationFile] Returned FileNameInformation: {}", file_info.filename);
                    
                    if required_size > length {
                        (STATUS_BUFFER_OVERFLOW, length)
                    } else {
                        (STATUS_SUCCESS, required_size)
                    }
                }
            }
            
            FILE_POSITION_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_POSITION_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FilePositionInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    let info = FILE_POSITION_INFORMATION {
                        CurrentByteOffset: file_info.position as i64,
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FilePositionInformation: offset={}", file_info.position);
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_INTERNAL_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_INTERNAL_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileInternalInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    // Use handle as a unique file ID
                    let info = FILE_INTERNAL_INFORMATION {
                        IndexNumber: file_handle as i64,
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileInternalInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_ACCESS_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_ACCESS_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileAccessInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    let info = FILE_ACCESS_INFORMATION {
                        AccessFlags: file_info.access_mode,
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileAccessInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_MODE_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_MODE_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileModeInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    let info = FILE_MODE_INFORMATION {
                        Mode: file_info.creation_flags & 0xFF00FFFF,  // Mask out disposition
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileModeInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            FILE_ALIGNMENT_INFORMATION_CLASS => {
                let required_size = std::mem::size_of::<FILE_ALIGNMENT_INFORMATION>() as u32;
                if length < required_size {
                    log::warn!("[ZwQueryInformationFile] Buffer too small for FileAlignmentInformation");
                    (STATUS_INFO_LENGTH_MISMATCH, 0)
                } else {
                    let info = FILE_ALIGNMENT_INFORMATION {
                        AlignmentRequirement: 0,  // No alignment requirement
                    };
                    memory::write_struct(emu, file_info_ptr, &info)?;
                    log::info!("[ZwQueryInformationFile] Returned FileAlignmentInformation");
                    (STATUS_SUCCESS, required_size)
                }
            }
            
            _ => {
                log::warn!("[ZwQueryInformationFile] Unsupported FileInformationClass: {}", info_class);
                (STATUS_INVALID_INFO_CLASS, 0)
            }
        }
    } else {
        log::error!("[ZwQueryInformationFile] Invalid handle: 0x{:x}", file_handle);
        (STATUS_INVALID_HANDLE, 0)
    };
    
    // Write IO_STATUS_BLOCK
    if io_status_block_ptr != 0 {
        let io_status = IO_STATUS_BLOCK {
            Anonymous: IO_STATUS_BLOCK_0 {
                Status: status as i32,
            },
            Information: bytes_written as usize,
        };
        memory::write_struct(emu, io_status_block_ptr, &io_status)?;
    }
    
    // Return NTSTATUS
    emu.reg_write(RegisterX86::RAX, status as u64)?;
    
    log::info!("[ZwQueryInformationFile] Returning status: 0x{:08x}", status);
    
    Ok(())
}