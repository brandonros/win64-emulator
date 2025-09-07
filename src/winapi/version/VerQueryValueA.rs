/*
VerQueryValueA function (winver.h)
02/08/2023
Retrieves specified version information from the specified version-information resource. To retrieve the appropriate resource, before you call VerQueryValue, you must first call the GetFileVersionInfoSize function, and then the GetFileVersionInfo function.

Syntax
C++

Copy
BOOL VerQueryValueA(
  [in]  LPCVOID pBlock,
  [in]  LPCSTR  lpSubBlock,
  [out] LPVOID  *lplpBuffer,
  [out] PUINT   puLen
);
Parameters
[in] pBlock

Type: LPCVOID

The version-information resource returned by the GetFileVersionInfo function.

[in] lpSubBlock

Type: LPCTSTR

The version-information value to be retrieved. The string must consist of names separated by backslashes (\) and it must have one of the following forms.

\
The root block. The function retrieves a pointer to the VS_FIXEDFILEINFO structure for the version-information resource.

\VarFileInfo\Translation
The translation array in a Var variable information structure—the Value member of this structure. The function retrieves a pointer to this array of language and code page identifiers. An application can use these identifiers to access a language-specific StringTable structure (using the szKey member) in the version-information resource.

\StringFileInfo\lang-codepage\string-name
A value in a language-specific StringTable structure. The lang-codepage name is a concatenation of a language and code page identifier pair found as a DWORD in the translation array for the resource. Here the lang-codepage name must be specified as a hexadecimal string. The string-name name must be one of the predefined strings described in the following Remarks section. The function retrieves a string value specific to the language and code page indicated.

[out] lplpBuffer

Type: LPVOID*

When this method returns, contains the address of a pointer to the requested version information in the buffer pointed to by pBlock. The memory pointed to by lplpBuffer is freed when the associated pBlock memory is freed.

[out] puLen

Type: PUINT

When this method returns, contains a pointer to the size of the requested data pointed to by lplpBuffer: for version information values, the length in characters of the string stored at lplpBuffer; for translation array values, the size in bytes of the array stored at lplpBuffer; and for root block, the size in bytes of the structure.

Return value
Type: BOOL

If the specified version-information structure exists, and version information is available, the return value is nonzero. If the address of the length buffer is zero, no value is available for the specified version-information name.

If the specified name does not exist or the specified resource is not valid, the return value is zero.

Remarks
This function works on 16-, 32-, and 64-bit file images.

The following are predefined version information Unicode strings.

Comments	InternalName	ProductName
CompanyName	LegalCopyright	ProductVersion
FileDescription	LegalTrademarks	PrivateBuild
FileVersion	OriginalFilename	SpecialBuild
 
Examples
The following example shows how to enumerate the available version languages and retrieve the FileDescription string-value for each language.

Be sure to call the GetFileVersionInfoSize and GetFileVersionInfo functions before calling VerQueryValue to properly initialize the pBlock buffer.

C++

Copy
// Structure used to store enumerated languages and code pages.

HRESULT hr;

struct LANGANDCODEPAGE {
  WORD wLanguage;
  WORD wCodePage;
} *lpTranslate;

// Read the list of languages and code pages.

VerQueryValue(pBlock, 
              TEXT("\\VarFileInfo\\Translation"),
              (LPVOID*)&lpTranslate,
              &cbTranslate);

// Read the file description for each language and code page.

for( i=0; i < (cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
{
  hr = StringCchPrintf(SubBlock, 50,
            TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"),
            lpTranslate[i].wLanguage,
            lpTranslate[i].wCodePage);
	if (FAILED(hr))
	{
	// TODO: write error handler.
	}

  // Retrieve file description for language and code page "i". 
  VerQueryValue(pBlock, 
                SubBlock, 
                &lpBuffer, 
                &dwBytes); 
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;
use crate::winapi;
use windows_sys::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;

pub fn VerQueryValueA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL VerQueryValueA(
    //   LPCVOID pBlock,      // RCX
    //   LPCSTR  lpSubBlock,  // RDX
    //   LPVOID  *lplpBuffer, // R8
    //   PUINT   puLen        // R9
    // )
    
    let pblock = emu.reg_read(X86Register::RCX)?;
    let subblock_ptr = emu.reg_read(X86Register::RDX)?;
    let buffer_ptr_ptr = emu.reg_read(X86Register::R8)?;
    let len_ptr = emu.reg_read(X86Register::R9)?;
    
    // Read the subblock string
    let subblock = memory::read_string_from_memory(emu, subblock_ptr)?;
    
    log::info!(
        "[VerQueryValueA] pBlock: 0x{:x}, lpSubBlock: \"{}\", lplpBuffer: 0x{:x}, puLen: 0x{:x}",
        pblock, subblock, buffer_ptr_ptr, len_ptr
    );
    
    // Check for root block query (\\)
    if subblock == "\\" {
        // Return pointer to VS_FIXEDFILEINFO structure
        // The VS_FIXEDFILEINFO should be at offset after the VS_VERSIONINFO header
        // and the "VS_VERSION_INFO\0" wide string
        
        // Calculate offset to VS_FIXEDFILEINFO
        // Header (6 bytes) + "VS_VERSION_INFO\0" (32 bytes for wide string) + padding
        let fixed_info_offset = 0x28; // Aligned offset where we wrote VS_FIXEDFILEINFO
        let fixed_info_ptr = pblock + fixed_info_offset;
        
        // Write the pointer to the buffer
        emu.mem_write(buffer_ptr_ptr, &fixed_info_ptr.to_le_bytes()[..8])?;
        
        // Write the length
        let fixed_info_size = std::mem::size_of::<VS_FIXEDFILEINFO>() as u32;
        emu.mem_write(len_ptr, &fixed_info_size.to_le_bytes())?;
        
        log::info!(
            "[VerQueryValueA] Returning VS_FIXEDFILEINFO at 0x{:x}, size: {}",
            fixed_info_ptr, fixed_info_size
        );
        
        // Return TRUE
        emu.reg_write(X86Register::RAX, 1)?;
    } else if subblock == "\\VarFileInfo\\Translation" {
        // Return translation array (language and code page identifiers)
        // For simplicity, return US English (0x0409) with Unicode code page (0x04B0)
        
        // Allocate space for translation array
        let translation_addr = match HEAP_ALLOCATIONS.allocate(emu, 4) {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("[VerQueryValueA] Failed to allocate memory: {}", e);
                emu.reg_write(X86Register::RAX, 0)?; // FALSE
                return Ok(());
            }
        };
        
        // Write language ID (0x0409) and code page (0x04B0)
        let translation: u32 = 0x04B00409; // CodePage << 16 | LanguageID
        emu.mem_write(translation_addr, &translation.to_le_bytes())?;
        
        // Write the pointer to the buffer
        emu.mem_write(buffer_ptr_ptr, &translation_addr.to_le_bytes()[..8])?;
        
        // Write the length (4 bytes for one DWORD)
        let translation_size: u32 = 4;
        emu.mem_write(len_ptr, &translation_size.to_le_bytes())?;
        
        log::info!(
            "[VerQueryValueA] Returning translation array at 0x{:x}, size: {}",
            translation_addr, translation_size
        );
        
        // Return TRUE
        emu.reg_write(X86Register::RAX, 1)?;
    } else if subblock.starts_with("\\StringFileInfo\\") {
        // Parse string query like \StringFileInfo\040904B0\FileDescription
        let parts: Vec<&str> = subblock.split('\\').collect();
        
        if parts.len() >= 4 {
            let string_name = parts[3];
            
            // Return mock string values based on the string name
            let string_value = match string_name {
                "FileDescription" => "Windows Common Controls",
                "FileVersion" => "6.10.22621.4541",
                "ProductVersion" => "10.0.22621.4541",
                "CompanyName" => "Microsoft Corporation",
                "ProductName" => "Microsoft® Windows® Operating System",
                "LegalCopyright" => "© Microsoft Corporation. All rights reserved.",
                "OriginalFilename" => "COMCTL32.DLL",
                "InternalName" => "COMCTL32",
                _ => "Unknown",
            };
            
            // Allocate and write the string
            let string_addr = match HEAP_ALLOCATIONS.allocate(emu, string_value.len() + 1) {
                Ok(addr) => addr,
                Err(e) => {
                    log::error!("[VerQueryValueA] Failed to allocate memory: {}", e);
                    emu.reg_write(X86Register::RAX, 0)?; // FALSE
                    return Ok(());
                }
            };
            memory::write_string_to_memory(emu, string_addr, string_value)?;
            
            // Write the pointer to the buffer
            emu.mem_write(buffer_ptr_ptr, &string_addr.to_le_bytes()[..8])?;
            
            // Write the length (string length in characters, not including null)
            let string_len = string_value.len() as u32;
            emu.mem_write(len_ptr, &string_len.to_le_bytes())?;
            
            log::info!(
                "[VerQueryValueA] Returning string '{}': '{}' at 0x{:x}, length: {}",
                string_name, string_value, string_addr, string_len
            );
            
            // Return TRUE
            emu.reg_write(X86Register::RAX, 1)?;
        } else {
            log::warn!("[VerQueryValueA] Invalid StringFileInfo query: {}", subblock);
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_RESOURCE_NAME_NOT_FOUND)?;
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
        }
    } else {
        log::warn!("[VerQueryValueA] Unknown subblock: {}", subblock);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_RESOURCE_NAME_NOT_FOUND)?;
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
    }
    
    Ok(())
}