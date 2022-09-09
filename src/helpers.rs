use crate::{
	error::{Error, Result},
	structures::{ExportTable, PeHeaders},
};
use core::{
	arch::asm,
	ffi::CStr,
	mem::MaybeUninit,
	slice,
	sync::atomic::{compiler_fence, Ordering},
};
use ntapi::{
	ntldr::LDR_DATA_TABLE_ENTRY,
	ntpebteb::{PEB, TEB},
	ntpsapi::PEB_LDR_DATA,
};
use windows_sys::Win32::Foundation::UNICODE_STRING;

const SYSCALL_TABLE_SIZE: usize = 512;
const LIBRARY_CONVERSION_BUFFER_SIZE: usize = 64;

#[cfg_attr(feature = "debug", inline(never))]
pub const fn fnv1a_hash_32_wstr(wchars: &[u16]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < wchars.len() {
		let c = unsafe { char::from_u32_unchecked(wchars[i] as u32).to_ascii_lowercase() };
		hash ^= c as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

#[cfg_attr(feature = "debug", inline(never))]
pub const fn fnv1a_hash_32(chars: &[u8]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < chars.len() {
		let c = unsafe { char::from_u32_unchecked(chars[i] as u32).to_ascii_lowercase() };
		hash ^= c as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn simple_memcpy(dest: *mut u8, src: *mut u8, len: usize) {
	let n_bytes = len; // Iterate backwards to avoid optimizing..?
	for i in (0..n_bytes).rev() {
		compiler_fence(Ordering::Acquire);
		unsafe { *dest.add(i) = *src.add(i) };
	}
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn simple_memset_u32(dest: &mut [MaybeUninit<u32>], value: u32) {
	let n_bytes = dest.len(); // Iterate backwards to avoid optimizing..?
	for i in (0..n_bytes).rev() {
		compiler_fence(Ordering::Acquire);
		unsafe { dest.get_unchecked_mut(i).write(value) };
	}
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn ascii_wstr_eq(ascii: &CStr, wstr: &[u16]) -> bool {
	// Check if the lengths are equal
	if wstr.len() != ascii.to_bytes().len() {
		return false;
	}

	// Check if they are equal
	if wstr
		.iter()
		.copied()
		.zip(ascii.to_bytes().iter().copied())
		.map(|(a, b)| ((a as u8).to_ascii_lowercase(), b.to_ascii_lowercase()))
		.any(|(a, b)| a != b)
	{
		return false;
	}
	true
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn ascii_ascii_eq(a: &[u8], b: &[u8]) -> bool {
	// Check if the lengths are equal
	if a.len() != b.len() {
		return false;
	}

	// Check if they are equal
	if a.iter()
		.copied()
		.zip(b.iter().copied())
		.map(|(a, b)| (a.to_ascii_lowercase(), b.to_ascii_lowercase()))
		.any(|(a, b)| a != b)
	{
		return false;
	}
	true
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_ip() -> usize {
	let rip: usize;
	#[cfg(target_arch = "x86_64")]
	unsafe {
		asm!("lea {rip}, [rip]", rip = out(reg) rip)
	};
	#[cfg(target_arch = "x86")]
	unsafe {
		asm!("lea {eip}, [eip]", rip = out(reg) rip)
	};
	rip
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_teb() -> &'static mut TEB {
	let teb: *mut TEB;
	unsafe {
		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
		#[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
	}
	let teb = unsafe { &mut *teb };
	teb
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_peb() -> &'static mut PEB {
	let teb = get_teb();
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };
	peb
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_pe_base(start: usize) -> Result<*mut u8> {
	let mut aligned = start & !0xfff;
	loop {
		if aligned == 0 {
			return Err(Error::SelfFind);
		}

		match PeHeaders::parse(aligned as _) {
			Ok(_) => break Ok(aligned as _),
			Err(_) => aligned -= 0x1000,
		}
	}
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_loaded_module_by_hash(ldr: &PEB_LDR_DATA, hash: u32) -> Result<*mut u8> {
	// Get initial entry in the list
	let mut ldr_data_ptr = ldr.InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
	while !ldr_data_ptr.is_null() {
		let ldr_data = unsafe { &*ldr_data_ptr };

		// Make a slice of wchars from the base name
		let dll_name = ldr_data.BaseDllName;
		let buffer = dll_name.Buffer;
		if buffer.is_null() {
			break;
		}
		let dll_name_wstr = unsafe { slice::from_raw_parts(buffer, dll_name.Length as usize / 2) };

		if fnv1a_hash_32_wstr(dll_name_wstr) != hash {
			// Go to the next entry
			ldr_data_ptr = ldr_data.InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
			continue;
		}

		// Return the base address for this DLL
		return Ok(ldr_data.DllBase as _);
	}
	Err(Error::ModuleByHash)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_loaded_module_by_ascii(ldr: &PEB_LDR_DATA, ascii: *const i8) -> Result<*mut u8> {
	let ascii = unsafe { CStr::from_ptr(ascii) };

	// Get initial entry in the list
	let mut ldr_data_ptr = ldr.InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
	while !ldr_data_ptr.is_null() {
		let ldr_data = unsafe { &*ldr_data_ptr };

		// Make a slice of wchars from the base name
		let dll_name = ldr_data.BaseDllName;
		let buffer = dll_name.Buffer;
		if buffer.is_null() {
			break;
		}
		let dll_name_wstr = unsafe { slice::from_raw_parts(buffer, dll_name.Length as usize / 2) };

		if ascii_wstr_eq(ascii, dll_name_wstr) {
			return Ok(ldr_data.DllBase as _);
		}

		// Go to the next entry
		ldr_data_ptr = ldr_data.InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
	}
	Err(Error::ModuleByAscii)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_export_by_hash(exports: &ExportTable, base: *mut u8, hash: u32) -> Result<*mut u8> {
	exports
		.iter_string_addr(base)
		.find(|(name, _)| fnv1a_hash_32(name.to_bytes()) == hash)
		.map(|(_, addr)| addr)
		.ok_or(Error::ExportVaByHash)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_export_by_ascii(
	exports: &ExportTable,
	base: *mut u8,
	string: &CStr,
) -> Result<*mut u8> {
	exports
		.iter_string_addr(base)
		.find(|(name, _)| ascii_ascii_eq(name.to_bytes(), string.to_bytes()))
		.map(|(_, addr)| addr)
		.ok_or(Error::ExportVaByAscii)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_library_base(
	peb_ldr: &PEB_LDR_DATA,
	library_name: *const u8,
	load_child_dll: &dyn Fn(*const UNICODE_STRING) -> Result<*mut u8>,
) -> Result<*mut u8> {
	let loaded_library_base = match find_loaded_module_by_ascii(peb_ldr, library_name as _) {
		Ok(base) => base,
		Err(_) => {
			let name_ascii = unsafe { CStr::from_ptr(library_name as _) };

			let mut buffer_space = [MaybeUninit::uninit(); LIBRARY_CONVERSION_BUFFER_SIZE];
			buffer_space
				.iter_mut()
				.zip(name_ascii.to_bytes_with_nul().iter())
				.for_each(|(wchar, &ascii)| {
					wchar.write(ascii as u16);
				});

			let unicode_string = UNICODE_STRING {
				Length: (name_ascii.to_bytes().len() * 2) as _,
				MaximumLength: (name_ascii.to_bytes_with_nul().len() * 2) as _,
				Buffer: MaybeUninit::slice_as_ptr(&buffer_space) as _,
			};

			// Now load the library
			load_child_dll(&unicode_string as _)?
		}
	};
	if loaded_library_base.is_null() {
		return Err(Error::LdrLoadDll);
	}
	Ok(loaded_library_base)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn syscall_table(exports: &ExportTable, base: *mut u8) -> [u32; SYSCALL_TABLE_SIZE] {
	let mut scratch_table = [MaybeUninit::<(u32, *mut u8)>::uninit(); SYSCALL_TABLE_SIZE];
	let mut num_syscalls = 0;

	// Iterate through exports which match the names of syscalls
	exports
		.iter_string_addr(base)
		.filter(|(name, _)| {
			// Our condition is - name must start with zW
			let name = name.to_bytes();
			let name_0 = match name.get(0) {
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

	let mut output = [MaybeUninit::uninit(); SYSCALL_TABLE_SIZE];

	simple_memset_u32(&mut output, 0);

	let mut output = unsafe { MaybeUninit::array_assume_init(output) };

	// Copy hashes over to output slice
	for i in 0..num_syscalls {
		unsafe { *output.get_unchecked_mut(i) = working_slice.get_unchecked(i).0 };
	}
	output
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_syscall_by_hash(table: &[u32; SYSCALL_TABLE_SIZE], hash: u32) -> Result<u32> {
	table
		.iter()
		.position(|&table_hash| table_hash == hash)
		.map(|x| x as u32)
		.ok_or(Error::SyscallNumber)
}
