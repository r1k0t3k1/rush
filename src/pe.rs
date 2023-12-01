use crate::fnv1a_hash;
use crate::CStr;

pub struct PE {
	base_address: usize
}  

impl PE {
	pub fn new(base_address: usize) -> Self {
		PE { base_address }
	}

	fn get_e_lfanew(&self) -> u32 {
		unsafe{*((self.base_address + 0x3c) as *const u32)}
	}

    fn get_image_nt_headers(&self) -> usize {
        self.base_address + self.get_e_lfanew() as usize
    }

    fn get_image_optional_header(&self) -> usize {
        self.get_image_nt_headers() + 0x18
    }

    fn get_image_directory_entry_export(&self) -> usize {
        //self.get_image_optional_header() + 0x60 // for x86
        self.get_image_optional_header() + 0x70
    }

    fn get_export_directory_rva(&self) -> u32 {
        unsafe{ *(self.get_image_directory_entry_export() as *const u32) }
    }

    fn get_export_directory_va(&self) -> usize {
        self.base_address + self.get_export_directory_rva() as usize
    }

    pub fn get_function_address(&self, function_hash: usize) -> Option<*const ()> {
        let va = self.get_export_directory_va();
        let number_of_functions: u32 = unsafe{ *((va + 0x14) as *const u32) };
        let address_of_functions: u32 = unsafe{ *((va + 0x1c) as *const u32) };
        let address_of_names: u32 = unsafe{ *((va + 0x20) as *const u32) };
        let address_of_name_ordinals: u32 = unsafe{ *((va + 0x24) as *const u32) };
        
        let names_va: usize = self.base_address + address_of_names as usize;
        
        let fn_name_va_addresses = unsafe{ core::slice::from_raw_parts(names_va as *const u32, number_of_functions as usize) };
        let name_ordinals =  unsafe{ core::slice::from_raw_parts(
                (self.base_address + address_of_name_ordinals as usize) as *const u16,
                number_of_functions as usize)
        };

        let name_index = fn_name_va_addresses.iter().position(|x|
            fnv1a_hash((unsafe{ CStr::from_ptr((self.base_address + *x as usize) as *const i8) }).to_bytes()) == function_hash
        );

        if name_index == None {
            return None;
        }
        
        let function_addresses =  unsafe{ core::slice::from_raw_parts(
                (self.base_address + address_of_functions as usize) as *const u32,
                number_of_functions as usize)
        };

        let function_index = name_ordinals[name_index.unwrap()];
        
        Some((self.base_address + function_addresses[function_index as usize] as usize) as *const ())
    }
}
