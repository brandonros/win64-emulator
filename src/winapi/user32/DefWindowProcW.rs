use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

// Common Windows messages
const WM_NULL: u32 = 0x0000;
const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_MOVE: u32 = 0x0003;
const WM_SIZE: u32 = 0x0005;
const WM_ACTIVATE: u32 = 0x0006;
const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_ENABLE: u32 = 0x000A;
const WM_SETREDRAW: u32 = 0x000B;
const WM_SETTEXT: u32 = 0x000C;
const WM_GETTEXT: u32 = 0x000D;
const WM_GETTEXTLENGTH: u32 = 0x000E;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_SYSCOLORCHANGE: u32 = 0x0015;
const WM_SHOWWINDOW: u32 = 0x0018;
const WM_ACTIVATEAPP: u32 = 0x001C;
const WM_SETCURSOR: u32 = 0x0020;
const WM_MOUSEACTIVATE: u32 = 0x0021;
const WM_GETMINMAXINFO: u32 = 0x0024;
const WM_WINDOWPOSCHANGING: u32 = 0x0046;
const WM_WINDOWPOSCHANGED: u32 = 0x0047;
const WM_NCCREATE: u32 = 0x0081;
const WM_NCDESTROY: u32 = 0x0082;
const WM_NCCALCSIZE: u32 = 0x0083;
const WM_NCHITTEST: u32 = 0x0084;
const WM_NCPAINT: u32 = 0x0085;
const WM_NCACTIVATE: u32 = 0x0086;
const WM_GETDLGCODE: u32 = 0x0087;
const WM_NCMOUSEMOVE: u32 = 0x00A0;
const WM_NCLBUTTONDOWN: u32 = 0x00A1;
const WM_NCLBUTTONUP: u32 = 0x00A2;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_SYSCOMMAND: u32 = 0x0112;
const WM_TIMER: u32 = 0x0113;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_USER: u32 = 0x0400;

// NCHITTEST return values
const HTCLIENT: i64 = 1;
const HTCAPTION: i64 = 2;

// MA_ACTIVATE for WM_MOUSEACTIVATE
const MA_ACTIVATE: i64 = 1;

pub fn DefWindowProcW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // LRESULT DefWindowProcW(
    //   [in] HWND   hWnd,    // RCX
    //   [in] UINT   Msg,     // RDX
    //   [in] WPARAM wParam,  // R8
    //   [in] LPARAM lParam   // R9
    // )
    
    let hwnd = emu.reg_read(X86Register::RCX)?;
    let msg = emu.reg_read(X86Register::RDX)? as u32;
    let wparam = emu.reg_read(X86Register::R8)?;
    let lparam = emu.reg_read(X86Register::R9)?;
    
    let msg_name = match msg {
        WM_NULL => "WM_NULL",
        WM_CREATE => "WM_CREATE",
        WM_DESTROY => "WM_DESTROY",
        WM_MOVE => "WM_MOVE",
        WM_SIZE => "WM_SIZE",
        WM_ACTIVATE => "WM_ACTIVATE",
        WM_SETFOCUS => "WM_SETFOCUS",
        WM_KILLFOCUS => "WM_KILLFOCUS",
        WM_ENABLE => "WM_ENABLE",
        WM_SETREDRAW => "WM_SETREDRAW",
        WM_SETTEXT => "WM_SETTEXT",
        WM_GETTEXT => "WM_GETTEXT",
        WM_GETTEXTLENGTH => "WM_GETTEXTLENGTH",
        WM_PAINT => "WM_PAINT",
        WM_CLOSE => "WM_CLOSE",
        WM_QUIT => "WM_QUIT",
        WM_ERASEBKGND => "WM_ERASEBKGND",
        WM_SYSCOLORCHANGE => "WM_SYSCOLORCHANGE",
        WM_SHOWWINDOW => "WM_SHOWWINDOW",
        WM_ACTIVATEAPP => "WM_ACTIVATEAPP",
        WM_SETCURSOR => "WM_SETCURSOR",
        WM_MOUSEACTIVATE => "WM_MOUSEACTIVATE",
        WM_GETMINMAXINFO => "WM_GETMINMAXINFO",
        WM_WINDOWPOSCHANGING => "WM_WINDOWPOSCHANGING",
        WM_WINDOWPOSCHANGED => "WM_WINDOWPOSCHANGED",
        WM_NCCREATE => "WM_NCCREATE",
        WM_NCDESTROY => "WM_NCDESTROY",
        WM_NCCALCSIZE => "WM_NCCALCSIZE",
        WM_NCHITTEST => "WM_NCHITTEST",
        WM_NCPAINT => "WM_NCPAINT",
        WM_NCACTIVATE => "WM_NCACTIVATE",
        WM_GETDLGCODE => "WM_GETDLGCODE",
        WM_NCMOUSEMOVE => "WM_NCMOUSEMOVE",
        WM_NCLBUTTONDOWN => "WM_NCLBUTTONDOWN",
        WM_NCLBUTTONUP => "WM_NCLBUTTONUP",
        WM_KEYDOWN => "WM_KEYDOWN",
        WM_KEYUP => "WM_KEYUP",
        WM_CHAR => "WM_CHAR",
        WM_SYSCOMMAND => "WM_SYSCOMMAND",
        WM_TIMER => "WM_TIMER",
        WM_MOUSEMOVE => "WM_MOUSEMOVE",
        WM_LBUTTONDOWN => "WM_LBUTTONDOWN",
        WM_LBUTTONUP => "WM_LBUTTONUP",
        WM_RBUTTONDOWN => "WM_RBUTTONDOWN",
        WM_RBUTTONUP => "WM_RBUTTONUP",
        WM_MBUTTONDOWN => "WM_MBUTTONDOWN",
        WM_MBUTTONUP => "WM_MBUTTONUP",
        WM_MOUSEWHEEL => "WM_MOUSEWHEEL",
        _ if msg >= WM_USER => "WM_USER+",
        _ => "Unknown",
    };
    
    log::info!("[DefWindowProcW] hWnd: 0x{:x}, Msg: 0x{:04x} ({}), wParam: 0x{:x}, lParam: 0x{:x}",
        hwnd, msg, msg_name, wparam, lparam);
    
    // Provide default handling for common messages
    let result = match msg {
        WM_NCCREATE | WM_CREATE => {
            // Creation messages - return TRUE to continue
            log::info!("[DefWindowProcW] {} - returning TRUE", msg_name);
            1
        }
        
        WM_NCDESTROY | WM_DESTROY => {
            // Destruction messages - return 0
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_CLOSE => {
            // Default action for WM_CLOSE is to destroy the window
            log::info!("[DefWindowProcW] WM_CLOSE - default action would destroy window");
            0
        }
        
        WM_ERASEBKGND => {
            // Return non-zero to indicate we erased the background
            log::info!("[DefWindowProcW] WM_ERASEBKGND - returning TRUE");
            1
        }
        
        WM_NCACTIVATE => {
            // Return TRUE to continue processing
            log::info!("[DefWindowProcW] WM_NCACTIVATE - returning TRUE");
            1
        }
        
        WM_NCHITTEST => {
            // Return HTCLIENT to indicate the cursor is in the client area
            log::info!("[DefWindowProcW] WM_NCHITTEST - returning HTCLIENT");
            HTCLIENT
        }
        
        WM_MOUSEACTIVATE => {
            // Return MA_ACTIVATE to activate the window
            log::info!("[DefWindowProcW] WM_MOUSEACTIVATE - returning MA_ACTIVATE");
            MA_ACTIVATE
        }
        
        WM_SETCURSOR => {
            // Return FALSE to allow further processing
            log::info!("[DefWindowProcW] WM_SETCURSOR - returning FALSE");
            0
        }
        
        WM_GETMINMAXINFO => {
            // Return 0 - default min/max info is fine
            log::info!("[DefWindowProcW] WM_GETMINMAXINFO - returning 0");
            0
        }
        
        WM_WINDOWPOSCHANGING | WM_WINDOWPOSCHANGED => {
            // Return 0 to allow the change
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_NCCALCSIZE => {
            // Return 0 for default processing
            log::info!("[DefWindowProcW] WM_NCCALCSIZE - returning 0");
            0
        }
        
        WM_PAINT | WM_NCPAINT => {
            // Return 0 - painting handled
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_GETTEXT => {
            // Return 0 - no text
            log::info!("[DefWindowProcW] WM_GETTEXT - returning 0 (no text)");
            0
        }
        
        WM_GETTEXTLENGTH => {
            // Return 0 - no text
            log::info!("[DefWindowProcW] WM_GETTEXTLENGTH - returning 0");
            0
        }
        
        WM_SETTEXT => {
            // Return TRUE for success
            log::info!("[DefWindowProcW] WM_SETTEXT - returning TRUE");
            1
        }
        
        WM_SIZE | WM_MOVE | WM_SHOWWINDOW => {
            // Return 0 - message processed
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_ACTIVATE | WM_SETFOCUS | WM_KILLFOCUS => {
            // Return 0 - message processed
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_KEYDOWN | WM_KEYUP | WM_CHAR => {
            // Return 0 - message processed
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_MOUSEMOVE | WM_LBUTTONDOWN | WM_LBUTTONUP | 
        WM_RBUTTONDOWN | WM_RBUTTONUP | WM_MBUTTONDOWN | 
        WM_MBUTTONUP | WM_MOUSEWHEEL => {
            // Return 0 - message processed
            log::info!("[DefWindowProcW] {} - returning 0", msg_name);
            0
        }
        
        WM_SYSCOMMAND => {
            // Return 0 - command processed
            log::info!("[DefWindowProcW] WM_SYSCOMMAND - returning 0");
            0
        }
        
        _ => {
            // For unknown messages, return 0
            log::info!("[DefWindowProcW] Unhandled message 0x{:04x} - returning 0", msg);
            0
        }
    };
    
    // Return the result
    emu.reg_write(X86Register::RAX, result as u64)?;
    
    Ok(())
}