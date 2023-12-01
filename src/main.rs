//#![no_std]
//#![no_main]

use core::ffi::CStr;

mod hash;
use hash::fnv1a_hash;

mod util;

mod ldr;
use ldr::*;

mod pe;
use pe::PE;

//pub extern "C" fn _start() -> ! {
//    loop{}
//}
//
//#[panic_handler]
//fn panic(_info: &core::panic::PanicInfo) -> ! {
//    loop {}
//}

//#[no_mangle]
//pub extern "stdcall" fn main() {
fn main() {
    let ldr_list = LDR_DATA_TABLE_LIST::new();
    let mut kernel32_address: usize = 0;
    for l in ldr_list {
        if fnv1a_hash(l.BaseDllName.to_string().as_bytes()) == 0x7d52b10b2b6fca23 {
            kernel32_address = l.DllBase as usize;
        } 
    }

    if kernel32_address == 0 {
        return; 
    }
    
    let pe = PE::new(kernel32_address);
    let LoadLibraryA_addr = pe.get_function_address(0x69d265fe6b1c110f);
    if LoadLibraryA_addr.is_none() {
        return;
    }

    let LoadLibraryA: extern "stdcall" fn(*const u8) -> *const usize = unsafe{ core::mem::transmute(LoadLibraryA_addr.unwrap()) };
    let dll_name = unsafe{ CStr::from_bytes_with_nul_unchecked(b"user32.dll\0") };
    let HRESULT = LoadLibraryA("user32.dll\0".as_ptr() as *const u8);

    let mut user32_address: usize = 0;
    for l in ldr_list {
        if fnv1a_hash(l.BaseDllName.to_string().as_bytes()) == 0x4edb7e023b282399 {
            user32_address = l.DllBase as usize;
        } 
    }

    if user32_address == 0 {
        return; 
    }

    let user32 = PE::new(user32_address);
    let mut MessageBoxA_addr = user32.get_function_address(0x1e307d27ba21dda4);
    if MessageBoxA_addr.is_none() {
        return;
    }

    println!("MessageBoxA at: {:#x?}", MessageBoxA_addr);
    let MessageboxA: extern "stdcall" fn(usize, *const u8, *const u8, u32) -> *const u32 = unsafe{ core::mem::transmute(MessageBoxA_addr.unwrap()) };
    let h = MessageboxA(
        0,
        "Content\0".as_ptr(),
        "Title\0".as_ptr(),
        0
    );

    while true {}   

}

