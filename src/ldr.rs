use crate::util;

#[allow(non_snake_case)]
#[allow(dead_code)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    align: u32,
    BufferPtr: usize,
}

impl UNICODE_STRING {
    pub fn to_string(&self) -> String {
        let ptr = self.BufferPtr as *const u8;
        let arr = unsafe { core::slice::from_raw_parts(ptr, self.Length as usize) };
        let u16_slice = unsafe { &arr.align_to::<u16>().1 };
        return String::from_utf16(&u16_slice).unwrap();
    }
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks : u128,
    pub InMemoryOrderLinks: u128,
    pub InInitializationOrderLinks: u128,
    pub DllBase: u64,
    pub EntryPoint: u64,
    pub SizeOfImage: u64,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub FlagGroup: u64,
    pub ObsoleteLoadCount: u32,
    pub TlsIndex: u16,
    pub HashLinks: u16,
    pub TimeDateStamp: u64,
    pub EntryPointActivationContext: u32,
    pub Lock: u32,
    pub DdagNode: u32,
    pub NodeModuleLink: u32,
    pub LoadContext: u64,
    pub ParentDllBase: u32,
    pub SwitchBackContext : u32,
    pub BaseAddressIndexNode: u32,
    pub MappingInfoIndexNode1: u64,
    pub MappingInfoIndexNode2: u32,
    pub OriginalBase: u64,
    pub LoadTime: u64,
    pub BaseNameHashValue: u64,
    pub LoadReason: u32,
    pub ImplicitPathOptions: u32,
    pub ReferenceCount: u32,
    pub DependentLoadFlags: u32,
    pub SigningLevel: u32,
}

impl LDR_DATA_TABLE_ENTRY {
    fn new() -> Self {
        let imrml: usize = util::get_in_load_order_module_list_address();
        unsafe { *(imrml as *const LDR_DATA_TABLE_ENTRY) }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct LDR_DATA_TABLE_LIST {
    first: LDR_DATA_TABLE_ENTRY,
    current: LDR_DATA_TABLE_ENTRY,
}

impl LDR_DATA_TABLE_LIST {
    pub fn new() -> Self {
        LDR_DATA_TABLE_LIST {
            first: LDR_DATA_TABLE_ENTRY::new(),
            current: LDR_DATA_TABLE_ENTRY::new()
        }
    }
}

impl Iterator for LDR_DATA_TABLE_LIST {
    type Item = LDR_DATA_TABLE_ENTRY;

    fn next(&mut self) -> Option<Self::Item> {
        let mut return_data: LDR_DATA_TABLE_ENTRY;
        let mut next_ptr: usize = 0;

        if self.first == self.current {
            return_data = self.first;
            next_ptr = (self.first.InLoadOrderLinks & 0xffffffffffffffff) as usize;
        } else {
            return_data = self.current;
            next_ptr = (self.current.InLoadOrderLinks & 0xffffffffffffffff) as usize;
        }

        let next: LDR_DATA_TABLE_ENTRY = unsafe { *(next_ptr as *const LDR_DATA_TABLE_ENTRY) };

        if self.current.SizeOfImage == 0 {
            return None;
        }

        self.current = next;
        return Some(return_data);
    }
}
