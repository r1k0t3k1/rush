pub fn fnv1a_hash(b: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    let FNV_offset_basis = 0xcbf29ce484222325;
    #[cfg(target_arch = "x86_64")]
    let FNV_prime = 0x100000001b3;

    #[cfg(target_arch = "x86")]
    let FNV_offset_basis = 0x811c9dc5;
    #[cfg(target_arch = "x86")]
    let FNV_prime = 0x01000193;

    let mut hash = FNV_offset_basis;

    b.iter().fold(hash, |acc,x| ((acc ^ *x as usize).wrapping_mul(FNV_prime)))
}
