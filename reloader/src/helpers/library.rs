use crate::{
	LoaderContext,
	error::{Error, Result},
	function_wrappers::load_dll,
	helpers::general::{
		LinkedListPointer, ascii_ascii_eq, ascii_wstr_eq, fnv1a_hash_32, fnv1a_hash_32_wstr,
	},
};
use core::{
	ffi::CStr,
	mem::{MaybeUninit, transmute},
	ptr::addr_of_mut,
};
use objparse::ExportTable;
use phnt::ffi::{LDR_DATA_TABLE_ENTRY, PEB_LDR_DATA, UNICODE_STRING, UNICODE_STRING64};

const LIBRARY_CONVERSION_BUFFER_SIZE: usize = 64;

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_library_base(
	peb_ldr: *mut PEB_LDR_DATA,
	library_name: *const u8,

	context: &LoaderContext,
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

			let unicode_string = UNICODE_STRING64 {
				Length: (name_ascii.to_bytes().len() * 2) as _,
				MaximumLength: (name_ascii.to_bytes_with_nul().len() * 2) as _,
				Buffer: MaybeUninit::slice_as_ptr(&buffer_space) as _,
			};

			let unicode_string =
				unsafe { transmute::<UNICODE_STRING64, UNICODE_STRING>(unicode_string) };

			// Now load the library
			load_dll(context.ldr_load_dll, &raw const unicode_string)?
		}
	};
	if loaded_library_base.is_null() {
		return Err(Error::LdrLoadDll);
	}
	Ok(loaded_library_base)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_loaded_module_by_hash(ldr: *mut PEB_LDR_DATA, hash: u32) -> Result<*mut u8> {
	// Get list head
	let head = unsafe { addr_of_mut!((*ldr).InLoadOrderModuleList) };
	// Get initial entry
	let first = unsafe { (*head).Flink };

	let mut iter = LinkedListPointer::new(first);

	while let Some(entry) = iter.next_until(head) {
		let ldr_data_ptr = entry as *mut LDR_DATA_TABLE_ENTRY;
		let ldr_data = unsafe { &*ldr_data_ptr };

		// Make a slice of wchars from the base name
		let dll_name = &ldr_data.BaseDllName;

		let dll_name_wstr = dll_name.as_slice();

		if fnv1a_hash_32_wstr(dll_name_wstr) == hash {
			// Return the base address for this DLL
			return Ok(ldr_data.DllBase as _);
		}
	}
	Err(Error::ModuleByHash)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_loaded_module_by_ascii(ldr: *mut PEB_LDR_DATA, ascii: *const i8) -> Result<*mut u8> {
	let ascii = unsafe { CStr::from_ptr(ascii) };

	// Get list head
	let head = unsafe { addr_of_mut!((*ldr).InLoadOrderModuleList) };
	// Get initial entry
	let first = unsafe { (*head).Flink };

	let mut iter = LinkedListPointer::new(first);

	while let Some(entry) = iter.next_until(head) {
		let ldr_data_ptr = entry as *mut LDR_DATA_TABLE_ENTRY;

		let ldr_data = unsafe { &*ldr_data_ptr };

		// Make a slice of wchars from the base name
		let dll_name = &ldr_data.BaseDllName;

		let dll_name_wstr = dll_name.as_slice();

		if ascii_wstr_eq(ascii, dll_name_wstr) {
			// Return the base address for this DLL
			return Ok(ldr_data.DllBase as _);
		}
	}
	Err(Error::ModuleByAscii)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_export_by_hash(exports: &ExportTable, base: *mut u8, hash: u32) -> Result<*mut u8> {
	unsafe {
		exports
			.iter_string_addr(base)
			.find(|(name, _)| fnv1a_hash_32(name.to_bytes()) == hash)
			.map(|(_, addr)| addr)
			.ok_or(Error::ExportVaByHash)
	}
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_export_by_ascii(
	exports: &ExportTable,
	base: *mut u8,
	string: &CStr,
) -> Result<*mut u8> {
	unsafe {
		exports
			.iter_string_addr(base)
			.find(|(name, _)| ascii_ascii_eq(name.to_bytes(), string.to_bytes()))
			.map(|(_, addr)| addr)
			.ok_or(Error::ExportVaByAscii)
	}
}
