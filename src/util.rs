use core::arch::asm;

pub extern "stdcall" fn get_in_memory_order_module_list_address() -> usize {
    let mut in_load_order_module_list: usize = 0;
    unsafe {
       asm!(
           "mov eax, dword ptr fs:[0x18]", // get TEB address.
           "mov eax, dword ptr [eax + 0x30]", // get PEB address.
           "mov eax, dword ptr [eax + 0x0c]", // get LDR address.
           "mov eax, dword ptr [eax + 0x14]", // get InMemoryOrderModuleList address.
           "sub eax, 0x8",
           "mov {0:e}, eax",
           out(reg) in_load_order_module_list,
       );
    }
    return in_load_order_module_list;
}

#[cfg(target_arch="x86_64")]
pub extern "stdcall" fn get_in_load_order_module_list_address() -> usize {
    let mut in_load_order_module_list: usize = 0;
    unsafe {
       asm!(
           "xor rax, rax",
           "mov rax, qword ptr gs:[0x30]", // get TEB address.
           "mov rax, [rax+0x60]",          // get PEB address.
           "mov rax, qword ptr [rax + 0x18]", // get LDR address.
           "mov rax, qword ptr [rax + 0x10]", // get InLoadOrderModuleList address.
           "mov {}, rax",
           out(reg) in_load_order_module_list,
       );
    }
    return in_load_order_module_list;
}

//#[allow(dead_code)]
//pub fn arr_hexdump(arr: &[u8]) {
//    println!("00010203 04050607 08091011 12131415\n-----------------------------------");
//    for (i,c) in arr.iter().enumerate() {
//        let ci = i + 1;
//        if ci == 1 {
//            print!("{:02x}", c);
//        } else if ci % 16 == 0 {
//            print!("{:02x}\n", c);
//        } else if ci % 4 == 0  {
//            print!("{:02x} ", c);
//        } else {
//            print!("{:02x}", c);
//        }
//    }
//}
