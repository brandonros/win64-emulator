use unicorn_engine::{Unicorn, RegisterX86};

use crate::emulation::memory;

// Locale information type constants
const LOCALE_ILANGUAGE: u32 = 0x1;
const LOCALE_SLANGUAGE: u32 = 0x2;
const LOCALE_SABBREVLANGNAME: u32 = 0x3;
const LOCALE_SNATIVELANGNAME: u32 = 0x4;
const LOCALE_ICOUNTRY: u32 = 0x5;
const LOCALE_SCOUNTRY: u32 = 0x6;
const LOCALE_SABBREVCTRYNAME: u32 = 0x7;
const LOCALE_SNATIVECTRYNAME: u32 = 0x8;
const LOCALE_IDEFAULTLANGUAGE: u32 = 0x9;
const LOCALE_IDEFAULTCOUNTRY: u32 = 0xA;
const LOCALE_IDEFAULTCODEPAGE: u32 = 0xB;
const LOCALE_SLIST: u32 = 0xC;
const LOCALE_IMEASURE: u32 = 0xD;
const LOCALE_SDECIMAL: u32 = 0xE;
const LOCALE_STHOUSAND: u32 = 0xF;
const LOCALE_SGROUPING: u32 = 0x10;
const LOCALE_IDIGITS: u32 = 0x11;
const LOCALE_ILZERO: u32 = 0x12;
const LOCALE_SNATIVEDIGITS: u32 = 0x13;
const LOCALE_SCURRENCY: u32 = 0x14;
const LOCALE_SINTLSYMBOL: u32 = 0x15;
const LOCALE_SMONDECIMALSEP: u32 = 0x16;
const LOCALE_SMONTHOUSANDSEP: u32 = 0x17;
const LOCALE_SMONGROUPING: u32 = 0x18;
const LOCALE_ICURRDIGITS: u32 = 0x19;
const LOCALE_IINTLCURRDIGITS: u32 = 0x1A;
const LOCALE_ICURRENCY: u32 = 0x1B;
const LOCALE_INEGCURR: u32 = 0x1C;
const LOCALE_SDATE: u32 = 0x1D;
const LOCALE_STIME: u32 = 0x1E;
const LOCALE_SSHORTDATE: u32 = 0x1F;
const LOCALE_SLONGDATE: u32 = 0x20;
const LOCALE_IDATE: u32 = 0x21;
const LOCALE_ILDATE: u32 = 0x22;
const LOCALE_ITIME: u32 = 0x23;
const LOCALE_ICENTURY: u32 = 0x24;
const LOCALE_ITLZERO: u32 = 0x25;
const LOCALE_IDAYLZERO: u32 = 0x26;
const LOCALE_IMONLZERO: u32 = 0x27;
const LOCALE_S1159: u32 = 0x28;
const LOCALE_S2359: u32 = 0x29;
const LOCALE_SDAYNAME1: u32 = 0x2A;
const LOCALE_SDAYNAME2: u32 = 0x2B;
const LOCALE_SDAYNAME3: u32 = 0x2C;
const LOCALE_SDAYNAME4: u32 = 0x2D;
const LOCALE_SDAYNAME5: u32 = 0x2E;
const LOCALE_SDAYNAME6: u32 = 0x2F;
const LOCALE_SDAYNAME7: u32 = 0x30;
const LOCALE_SABBREVDAYNAME1: u32 = 0x31;
const LOCALE_SABBREVDAYNAME2: u32 = 0x32;
const LOCALE_SABBREVDAYNAME3: u32 = 0x33;
const LOCALE_SABBREVDAYNAME4: u32 = 0x34;
const LOCALE_SABBREVDAYNAME5: u32 = 0x35;
const LOCALE_SABBREVDAYNAME6: u32 = 0x36;
const LOCALE_SABBREVDAYNAME7: u32 = 0x37;
const LOCALE_SMONTHNAME1: u32 = 0x38;
const LOCALE_SMONTHNAME2: u32 = 0x39;
const LOCALE_SMONTHNAME3: u32 = 0x3A;
const LOCALE_SMONTHNAME4: u32 = 0x3B;
const LOCALE_SMONTHNAME5: u32 = 0x3C;
const LOCALE_SMONTHNAME6: u32 = 0x3D;
const LOCALE_SMONTHNAME7: u32 = 0x3E;
const LOCALE_SMONTHNAME8: u32 = 0x3F;
const LOCALE_SMONTHNAME9: u32 = 0x40;
const LOCALE_SMONTHNAME10: u32 = 0x41;
const LOCALE_SMONTHNAME11: u32 = 0x42;
const LOCALE_SMONTHNAME12: u32 = 0x43;
const LOCALE_SABBREVMONTHNAME1: u32 = 0x44;
const LOCALE_SABBREVMONTHNAME2: u32 = 0x45;
const LOCALE_SABBREVMONTHNAME3: u32 = 0x46;
const LOCALE_SABBREVMONTHNAME4: u32 = 0x47;
const LOCALE_SABBREVMONTHNAME5: u32 = 0x48;
const LOCALE_SABBREVMONTHNAME6: u32 = 0x49;
const LOCALE_SABBREVMONTHNAME7: u32 = 0x4A;
const LOCALE_SABBREVMONTHNAME8: u32 = 0x4B;
const LOCALE_SABBREVMONTHNAME9: u32 = 0x4C;
const LOCALE_SABBREVMONTHNAME10: u32 = 0x4D;
const LOCALE_SABBREVMONTHNAME11: u32 = 0x4E;
const LOCALE_SABBREVMONTHNAME12: u32 = 0x4F;
const LOCALE_SPOSITIVESIGN: u32 = 0x50;
const LOCALE_SNEGATIVESIGN: u32 = 0x51;

// Additional constants
const LOCALE_STIMEFORMAT: u32 = 0x1003;
const LOCALE_IDEFAULTANSICODEPAGE: u32 = 0x1004;
const LOCALE_SYEARMONTH: u32 = 0x1006;
const LOCALE_SENGCURRNAME: u32 = 0x1007;
const LOCALE_SNATIVECURRNAME: u32 = 0x1008;
const LOCALE_INEGNUMBER: u32 = 0x1010;
const LOCALE_IDEFAULTMACCODEPAGE: u32 = 0x1011;
const LOCALE_SSORTNAME: u32 = 0x1013;
const LOCALE_IDIGITSUBSTITUTION: u32 = 0x1014;

// Custom/made-up values
const LOCALE_ICALENDARTYPE: u32 = 0x100A;
const LOCALE_IOPTIONALCALENDAR: u32 = 0x100B;
const LOCALE_IFIRSTDAYOFWEEK: u32 = 0x100C;
const LOCALE_IFIRSTWEEKOFYEAR: u32 = 0x100D;

pub fn GetLocaleInfoW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers
    let locale = emu.reg_read(RegisterX86::ECX)? as u32;
    let lctype = emu.reg_read(RegisterX86::EDX)? as u32;
    let lp_lc_data = emu.reg_read(RegisterX86::R8D)?;
    let cch_data = emu.reg_read(RegisterX86::R9D)? as u32;

    log::debug!("[GetLocaleInfoW] locale: 0x{:x} lctype: 0x{:x} buffer: 0x{:x} size: {}",
        locale, lctype, lp_lc_data, cch_data);

    // Get the locale string based on type
    let result = match lctype {
        LOCALE_SLANGUAGE => "English",
        LOCALE_SCOUNTRY => "United States",
        LOCALE_SLIST => ",",
        LOCALE_SDECIMAL => ".",
        LOCALE_STHOUSAND => ",",
        LOCALE_SCURRENCY => "$",
        LOCALE_SDATE => "/",
        LOCALE_STIME => ":",
        LOCALE_ICURRDIGITS => "2",
        LOCALE_IINTLCURRDIGITS => "2",
        LOCALE_ICURRENCY => "0",
        LOCALE_INEGCURR => "0",
        LOCALE_SSHORTDATE => "M/d/yyyy",
        LOCALE_SLONGDATE => "dddd, MMMM d, yyyy",
        LOCALE_IDATE => "0",
        LOCALE_ILDATE => "0",
        LOCALE_ITIME => "0",
        LOCALE_ICENTURY => "1",
        LOCALE_ITLZERO => "0",
        LOCALE_IDAYLZERO => "0",
        LOCALE_IMONLZERO => "0",
        LOCALE_S1159 => "AM",
        LOCALE_S2359 => "PM",
        LOCALE_ICALENDARTYPE => "1",
        LOCALE_IOPTIONALCALENDAR => "1",
        LOCALE_IFIRSTDAYOFWEEK => "6",
        LOCALE_IFIRSTWEEKOFYEAR => "0",
        LOCALE_ICOUNTRY => "1",
        LOCALE_SDAYNAME1 => "Monday",
        LOCALE_SDAYNAME2 => "Tuesday",
        LOCALE_SDAYNAME3 => "Wednesday",
        LOCALE_SDAYNAME4 => "Thursday",
        LOCALE_SDAYNAME5 => "Friday",
        LOCALE_SDAYNAME6 => "Saturday",
        LOCALE_SDAYNAME7 => "Sunday",
        LOCALE_SMONTHNAME1 => "January",
        LOCALE_SMONTHNAME2 => "February",
        LOCALE_SMONTHNAME3 => "March",
        LOCALE_SMONTHNAME4 => "April",
        LOCALE_SMONTHNAME5 => "May",
        LOCALE_SMONTHNAME6 => "June",
        LOCALE_SMONTHNAME7 => "July",
        LOCALE_SMONTHNAME8 => "August",
        LOCALE_SMONTHNAME9 => "September",
        LOCALE_SMONTHNAME10 => "October",
        LOCALE_SMONTHNAME11 => "November",
        LOCALE_SMONTHNAME12 => "December",
        LOCALE_SABBREVMONTHNAME1 => "Jan",
        LOCALE_SABBREVMONTHNAME2 => "Feb",
        LOCALE_SABBREVMONTHNAME3 => "Mar",
        LOCALE_SABBREVMONTHNAME4 => "Apr",
        LOCALE_SABBREVMONTHNAME5 => "May",
        LOCALE_SABBREVMONTHNAME6 => "Jun",
        LOCALE_SABBREVMONTHNAME7 => "Jul",
        LOCALE_SABBREVMONTHNAME8 => "Aug",
        LOCALE_SABBREVMONTHNAME9 => "Sep",
        LOCALE_SABBREVMONTHNAME10 => "Oct",
        LOCALE_SABBREVMONTHNAME11 => "Nov",
        LOCALE_SABBREVMONTHNAME12 => "Dec",
        LOCALE_SABBREVDAYNAME1 => "Mon",
        LOCALE_SABBREVDAYNAME2 => "Tue",
        LOCALE_SABBREVDAYNAME3 => "Wed",
        LOCALE_SABBREVDAYNAME4 => "Thu",
        LOCALE_SABBREVDAYNAME5 => "Fri",
        LOCALE_SABBREVDAYNAME6 => "Sat",
        LOCALE_SABBREVDAYNAME7 => "Sun",
        LOCALE_ILANGUAGE => "0409",
        LOCALE_IDEFAULTLANGUAGE => "0409",
        LOCALE_IDEFAULTCOUNTRY => "1",
        LOCALE_IDEFAULTCODEPAGE => "1252",
        LOCALE_IMEASURE => "1",
        LOCALE_SGROUPING => "3;0",
        LOCALE_IDIGITS => "2",
        LOCALE_ILZERO => "1",
        LOCALE_SINTLSYMBOL => "USD",
        LOCALE_SMONDECIMALSEP => ".",
        LOCALE_SMONTHOUSANDSEP => ",",
        LOCALE_SMONGROUPING => "3;0",
        LOCALE_SPOSITIVESIGN => "",
        LOCALE_SNEGATIVESIGN => "-",
        LOCALE_STIMEFORMAT => "h:mm:ss tt",
        LOCALE_IDEFAULTANSICODEPAGE => "1252",
        LOCALE_SYEARMONTH => "MMMM yyyy",
        LOCALE_SENGCURRNAME => "US Dollar",
        LOCALE_SNATIVECURRNAME => "US Dollar",
        LOCALE_INEGNUMBER => "1",
        LOCALE_IDEFAULTMACCODEPAGE => "10000",
        LOCALE_SSORTNAME => "Default",
        LOCALE_IDIGITSUBSTITUTION => "1",
        _ => {
            log::warn!("[GetLocaleInfoW] Unhandled lctype: 0x{:x}", lctype);
            "."  // Default fallback
        }
    };

    // Calculate required size in characters (including null terminator)
    let required_size = (result.len() + 1) as u32;

    // If cch_data is 0, return required buffer size
    if cch_data == 0 {
        emu.reg_write(RegisterX86::EAX, required_size as u64)?;
        return Ok(());
    }

    // Validate buffer pointer
    if lp_lc_data == 0 {
        log::warn!("[GetLocaleInfoW] Invalid parameter - null buffer");
        // SetLastError(ERROR_INVALID_PARAMETER)
        emu.reg_write(RegisterX86::EAX, 0)?;
        return Ok(());
    }

    // Check if buffer is too small
    if cch_data < required_size {
        log::warn!("[GetLocaleInfoW] Buffer too small: {} < {}", cch_data, required_size);
        // SetLastError(ERROR_INSUFFICIENT_BUFFER)
        emu.reg_write(RegisterX86::EAX, 0)?;
        return Ok(());
    }

    // Write the wide string to memory
    memory::write_wide_string_to_memory(emu, lp_lc_data, result)?;
    
    // Return number of characters written (including null terminator)
    emu.reg_write(RegisterX86::EAX, required_size as u64)?;
    
    Ok(())
}
