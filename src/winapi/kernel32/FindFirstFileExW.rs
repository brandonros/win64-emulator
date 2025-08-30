/*
FindFirstFileExW function (fileapi.h)
02/08/2023
Searches a directory for a file or subdirectory with a name and attributes that match those specified.

For the most basic version of this function, see FindFirstFile.

To perform this operation as a transacted operation, use the FindFirstFileTransacted function.

Syntax
C++

Copy
HANDLE FindFirstFileExW(
  [in]  LPCWSTR            lpFileName,
  [in]  FINDEX_INFO_LEVELS fInfoLevelId,
  [out] LPVOID             lpFindFileData,
  [in]  FINDEX_SEARCH_OPS  fSearchOp,
        LPVOID             lpSearchFilter,
  [in]  DWORD              dwAdditionalFlags
);
Parameters
[in] lpFileName

The directory or path, and the file name. The file name can include wildcard characters, for example, an asterisk (*) or a question mark (?).

This parameter should not be NULL, an invalid string (for example, an empty string or a string that is missing the terminating null character), or end in a trailing backslash (\).

If the string ends with a wildcard, period, or directory name, the user must have access to the root and all subdirectories on the path.

In the of this function, the name is limited to MAX_PATH characters. To extend this limit to approximately 32,000 wide characters, call the Unicode version of the function (FindFirstFileExW), and prepend "\\?\" to the path. For more information, see Naming a File.

Tip  Starting in Windows 10, version 1607, for the unicode version of this function (FindFirstFileExW), you can opt-in to remove the MAX_PATH character limitation without prepending "\\?\". See the "Maximum Path Limitation" section of Naming Files, Paths, and Namespaces for details.
 
[in] fInfoLevelId

The information level of the returned data.

This parameter is one of the FINDEX_INFO_LEVELS enumeration values.

[out] lpFindFileData

A pointer to the buffer that receives the file data.

The pointer type is determined by the level of information that is specified in the fInfoLevelId parameter.

[in] fSearchOp

The type of filtering to perform that is different from wildcard matching.

This parameter is one of the FINDEX_SEARCH_OPS enumeration values.

lpSearchFilter

A pointer to the search criteria if the specified fSearchOp needs structured search information.

At this time, none of the supported fSearchOp values require extended search information. Therefore, this pointer must be NULL.

[in] dwAdditionalFlags

Specifies additional flags that control the search.

Value	Meaning
FIND_FIRST_EX_CASE_SENSITIVE
1
Searches are case-sensitive.
FIND_FIRST_EX_LARGE_FETCH
2
Uses a larger buffer for directory queries, which can increase performance of the find operation.
Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported until Windows Server 2008 R2 and Windows 7.

FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY
4
Limits the results to files that are physically on disk. This flag is only relevant when a file virtualization filter is present.
Return value
If the function succeeds, the return value is a search handle used in a subsequent call to FindNextFile or FindClose, and the lpFindFileData parameter contains information about the first file or directory found.

If the function fails or fails to locate files from the search string in the lpFileName parameter, the return value is INVALID_HANDLE_VALUE and the contents of lpFindFileData are indeterminate. To get extended error information, call the GetLastError function.

Remarks
The FindFirstFileEx function opens a search handle and returns information about the first file that the file system finds with a name that matches the specified pattern. This may or may not be the first file or directory that appears in a directory-listing application (such as the dir command) when given the same file name string pattern. This is because FindFirstFileEx does no sorting of the search results. For additional information, see FindNextFile.

The following list identifies some other search characteristics:

The search is performed strictly on the name of the file, not on any attributes such as a date or a file type.
The search includes the long and short file names.
An attempt to open a search with a trailing backslash always fails.
Passing an invalid string, NULL, or empty string for the lpFileName parameter is not a valid use of this function. Results in this case are undefined.
Note  In rare cases or on a heavily loaded system, file attribute information on NTFS file systems may not be current at the time this function is called. To be assured of getting the current NTFS file system file attributes, call the GetFileInformationByHandle function.
 
If the underlying file system does not support the specified type of filtering, other than directory filtering, FindFirstFileEx fails with the error ERROR_NOT_SUPPORTED. The application must use FINDEX_SEARCH_OPS type FileExSearchNameMatch and perform its own filtering.
After the search handle is established, use it in the FindNextFile function to search for other files that match the same pattern with the same filtering that is being performed. When the search handle is not needed, it should be closed by using the FindClose function.

As stated previously, you cannot use a trailing backslash (\) in the lpFileName input string for FindFirstFileEx, therefore it may not be obvious how to search root directories. If you want to see files or get the attributes of a root directory, the following options would apply:

To examine files in a root directory, you can use "C:\*" and step through the directory by using FindNextFile.
To get the attributes of a root directory, use the GetFileAttributes function.
Note  Prepending the string "\\?\" does not allow access to the root directory.
 
On network shares, you can use an lpFileName in the form of the following: "\\server\service\*". However, you cannot use an lpFileName that points to the share itself; for example, "\\server\service" is not valid.

To examine a directory that is not a root directory, use the path to that directory, without a trailing backslash. For example, an argument of "C:\Windows" returns information about the directory "C:\Windows", not about a directory or file in "C:\Windows". To examine the files and directories in "C:\Windows", use an lpFileName of "C:\Windows\*".

The following call:

C++

Copy
FindFirstFileEx( lpFileName, 
                 FindExInfoStandard, 
                 lpFindData, 
                 FindExSearchNameMatch, 
                 NULL, 
                 0 );
Is equivalent to the following call:

C++

Copy
FindFirstFile( lpFileName, lpFindData );
Be aware that some other thread or process could create or delete a file with this name between the time you query for the result and the time you act on the information. If this is a potential concern for your application, one possible solution is to use the CreateFile function with CREATE_NEW (which fails if the file exists) or OPEN_EXISTING (which fails if the file does not exist).

If you are writing a 32-bit application to list all the files in a directory and the application may be run on a 64-bit computer, you should call Wow64DisableWow64FsRedirection before calling FindFirstFileEx and call Wow64RevertWow64FsRedirection after the last call to FindNextFile. For more information, see File System Redirector.

If the path points to a symbolic link, the WIN32_FIND_DATA buffer contains information about the symbolic link, not the target.

In Windows 8 and Windows Server 2012, this function is supported by the following technologies.

Technology	Supported
Server Message Block (SMB) 3.0 protocol	Yes
SMB 3.0 Transparent Failover (TFO)	Yes
SMB 3.0 with Scale-out File Shares (SO)	Yes
Cluster Shared Volume File System (CsvFS)	Yes
Resilient File System (ReFS)	Yes
 
Examples
The following code shows a minimal use of FindFirstFileEx. This program is equivalent to the example in the FindFirstFile topic.

C++

Copy
#include <windows.h>
#include <tchar.h>
#include <stdio.h>

void _tmain(int argc, TCHAR *argv[])
{
   WIN32_FIND_DATA FindFileData;
   HANDLE hFind;

   if( argc != 2 )
   {
      _tprintf(TEXT("Usage: %s [target_file]\n"), argv[0]);
      return;
   }

   _tprintf (TEXT("Target file is %s\n"), argv[1]);
   hFind = FindFirstFileEx(argv[1], FindExInfoStandard, &FindFileData,
             FindExSearchNameMatch, NULL, 0);
   if (hFind == INVALID_HANDLE_VALUE) 
   {
      printf ("FindFirstFileEx failed (%d)\n", GetLastError());
      return;
   } 
   else 
   {
      _tprintf (TEXT("The first file found is %s\n"), 
                FindFileData.cFileName);
      FindClose(hFind);
   }
}

 Note

The fileapi.h header defines FindFirstFileEx as an alias that automatically selects the ANSI or Unicode version of this function based on the definition of the UNICODE preprocessor constant. Mixing usage of the encoding-neutral alias with code that is not encoding-neutral can lead to mismatches that result in compilation or runtime errors. For more information, see Conventions for Function Prototypes.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::utils::read_wide_string;
use crate::emulation::memory;
use crate::emulation::vfs::VIRTUAL_FS;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

// Store search state for FindNextFile
pub struct FindFileState {
    pub pattern: String,
    pub files: Vec<String>,
    pub current_index: usize,
}

pub static FIND_FILE_HANDLES: LazyLock<RwLock<HashMap<u64, FindFileState>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

pub fn FindFirstFileExW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HANDLE FindFirstFileExW(
    //   LPCWSTR            lpFileName,        // RCX
    //   FINDEX_INFO_LEVELS fInfoLevelId,      // RDX
    //   LPVOID             lpFindFileData,    // R8
    //   FINDEX_SEARCH_OPS  fSearchOp,         // R9
    //   LPVOID             lpSearchFilter,    // Stack [RSP+0x28]
    //   DWORD              dwAdditionalFlags  // Stack [RSP+0x30]
    // )
    
    let file_name_ptr = emu.reg_read(RegisterX86::RCX)?;
    let info_level = emu.reg_read(RegisterX86::RDX)?;
    let find_data_ptr = emu.reg_read(RegisterX86::R8)?;
    let search_op = emu.reg_read(RegisterX86::R9)?;
    
    // Read stack parameters
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut search_filter_bytes = [0u8; 8];
    let mut additional_flags_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x28, &mut search_filter_bytes)?;
    emu.mem_read(rsp + 0x30, &mut additional_flags_bytes)?;
    let search_filter = u64::from_le_bytes(search_filter_bytes);
    let additional_flags = u32::from_le_bytes(additional_flags_bytes);
    
    // Read the file name string
    let file_name = read_wide_string(emu, file_name_ptr);
    
    log::info!(
        "[FindFirstFileExW] lpFileName: \"{}\", fInfoLevelId: 0x{:x}, lpFindFileData: 0x{:x}, fSearchOp: 0x{:x}, lpSearchFilter: 0x{:x}, dwAdditionalFlags: 0x{:x}",
        file_name, info_level, find_data_ptr, search_op, search_filter, additional_flags
    );
    
    const INVALID_HANDLE_VALUE: u64 = 0xFFFFFFFFFFFFFFFF;
    
    // Search for files using VFS
    let files = {
        let vfs = VIRTUAL_FS.read().unwrap();
        vfs.find_files(&file_name)
    };
    
    if files.is_empty() {
        log::info!("[FindFirstFileExW] No files found matching pattern: {}", file_name);
        emu.reg_write(RegisterX86::RAX, INVALID_HANDLE_VALUE)?;
        return Ok(());
    }
    
    // Create a search handle and store the results
    static NEXT_SEARCH_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x2000);
    let search_handle = NEXT_SEARCH_HANDLE.fetch_add(0x10, std::sync::atomic::Ordering::SeqCst);
    
    // Get the first file
    let first_file = files[0].clone();
    
    // Store search state
    {
        let mut handles = FIND_FILE_HANDLES.write().unwrap();
        handles.insert(search_handle, FindFileState {
            pattern: file_name.clone(),
            files: files.clone(),
            current_index: 1, // Start at 1 since we're returning the first file now
        });
    }
    
    // Populate WIN32_FIND_DATAW structure with the first file
    // This is a simplified version - real implementation would fill all fields
    if find_data_ptr != 0 {
        // WIN32_FIND_DATAW structure offsets
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        
        // Write dwFileAttributes at offset 0
        let attributes_bytes = FILE_ATTRIBUTE_NORMAL.to_le_bytes();
        emu.mem_write(find_data_ptr, &attributes_bytes)?;
        
        // Write cFileName at offset 0x2C (44 bytes)
        // Maximum path is 260 wide characters (520 bytes)
        let file_name_offset = find_data_ptr + 0x2C;
        memory::write_wide_string_to_memory(emu, file_name_offset, &first_file)?;
        
        log::info!("[FindFirstFileExW] Returning first file: {}", first_file);
    }
    
    // Return the search handle
    emu.reg_write(RegisterX86::RAX, search_handle)?;
    
    log::info!("[FindFirstFileExW] Created search handle 0x{:x}, found {} files", search_handle, files.len());
    
    Ok(())
}