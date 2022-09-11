use crate::{
	error::{Error, Result},
	helpers::general::fnv1a_hash_32,
	structures::ExportTable,
};
use core::mem::MaybeUninit;

pub const SYSCALL_TABLE_SIZE: usize = 512;

#[cfg_attr(feature = "debug", inline(never))]
pub fn gen_syscall_table(
	exports: &ExportTable,
	base: *mut u8,
	output: &mut [u32; SYSCALL_TABLE_SIZE],
) -> usize {
	let mut scratch_table = [MaybeUninit::<(u32, *mut u8)>::uninit(); SYSCALL_TABLE_SIZE];
	let mut num_syscalls = 0;

	// Iterate through exports which match the names of syscalls
	exports
		.iter_string_addr(base)
		.filter(|(name, _)| {
			// Our condition is - name must start with zW
			let name = name.to_bytes();
			let name_0 = match name.first() {
				Some(&x) => x,
				None => return false,
			};
			let name_1 = match name.get(1) {
				Some(&x) => x,
				None => return false,
			};
			if name_0 != b'Z' {
				return false;
			}
			if name_1 != b'w' {
				return false;
			}
			true
		})
		.enumerate()
		.for_each(|(n, (name, addr))| {
			// Turn each function name into a hash
			let name_hash = fnv1a_hash_32(name.to_bytes());

			unsafe { scratch_table.get_unchecked_mut(n).write((name_hash, addr)) };
			num_syscalls += 1;
		});

	let working_slice = unsafe {
		MaybeUninit::slice_assume_init_mut(scratch_table.get_unchecked_mut(..num_syscalls))
	};
	// Sort the filled entries by address
	working_slice.sort_unstable_by_key(|(_, addr)| *addr);

	// Copy hashes over to output slice
	for i in 0..num_syscalls {
		unsafe { *output.get_unchecked_mut(i) = working_slice.get_unchecked(i).0 };
	}
	num_syscalls
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_syscall_by_hash(table: &[u32; SYSCALL_TABLE_SIZE], hash: u32) -> Result<u32> {
	table
		.iter()
		.position(|&table_hash| table_hash == hash)
		.map(|x| x as u32)
		.ok_or(Error::SyscallNumber)
}
