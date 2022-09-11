use crate::{
	error::{Error, Result},
	helpers::general::{ascii_ascii_eq, ascii_wstr_eq, fnv1a_hash_32, fnv1a_hash_32_wstr},
	ntdll_wrappers::load_dll,
	structures::ExportTable,
	NtDllContext,
};
use core::{ffi::CStr, mem::MaybeUninit, slice};
use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpsapi::PEB_LDR_DATA};
use windows_sys::Win32::Foundation::UNICODE_STRING;

const LIBRARY_CONVERSION_BUFFER_SIZE: usize = 64;

#[cfg_attr(feature = "debug", inline(never))]
pub fn get_library_base(
	peb_ldr: *const PEB_LDR_DATA,
	library_name: *const u8,

	context: &NtDllContext,
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
			load_dll(context.ldr_load_dll, &unicode_string as _)?
		}
	};
	if loaded_library_base.is_null() {
		return Err(Error::LdrLoadDll);
	}
	Ok(loaded_library_base)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_loaded_module_by_hash(ldr: *const PEB_LDR_DATA, hash: u32) -> Result<*mut u8> {
	// Get initial entry in the list
	let mut ldr_data_ptr =
		unsafe { (*ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY };
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
pub fn find_loaded_module_by_ascii(ldr: *const PEB_LDR_DATA, ascii: *const i8) -> Result<*mut u8> {
	let ascii = unsafe { CStr::from_ptr(ascii) };

	// Get initial entry in the list
	let mut ldr_data_ptr =
		unsafe { (*ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY };
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
