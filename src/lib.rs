#![no_std]
#![feature(slice_split_at_unchecked)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_array_assume_init)]
#![feature(const_char_convert)]
#![feature(asm_const)]

mod error;
mod helpers;
mod structures;
mod syscall;

use crate::{
	error::{Error, Result},
	helpers::{
		find_export_by_ascii, find_export_by_hash, find_loaded_module_by_hash, find_pe,
		find_syscall_by_hash, fnv1a_hash_32, fnv1a_hash_32_wstr, get_library_base, simple_memcpy,
		syscall_table,
	},
	structures::PeHeaders,
	syscall::{syscall3, syscall5, syscall6},
};
use core::{
	arch::asm,
	mem::{size_of, transmute},
	ptr::null_mut,
	slice,
	str::from_utf8_unchecked,
};
use cstr_core::CStr;
use ntapi::{
	ntpebteb::TEB,
	winapi::um::winnt::{DLL_PROCESS_ATTACH, PAGE_NOACCESS},
};
use object::{
	pe::{
		ImageThunkData64, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_REL_BASED_ABSOLUTE,
		IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
		IMAGE_SCN_MEM_WRITE,
	},
	read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData},
	LittleEndian,
};
use wchar::wch;
use windows_sys::Win32::{
	Foundation::{STATUS_SUCCESS, UNICODE_STRING},
	System::Memory::{
		MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
		PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
	},
};

// Abusing fnv1a hash to find the strings we're looking for
// Can't just do a string comparison because the segments aren't properly loaded yet

const NTDLL_HASH: u32 = fnv1a_hash_32_wstr(wch!("ntdll.dll"));

const ZWFLUSHINSTRUCTIONCACHE_HASH: u32 = fnv1a_hash_32("ZwFlushInstructionCache".as_bytes());
const ZWALLOCATEVIRTUALMEMORY_HASH: u32 = fnv1a_hash_32("ZwAllocateVirtualMemory".as_bytes());
const ZWPROTECTVIRTUALMEMORY_HASH: u32 = fnv1a_hash_32("ZwProtectVirtualMemory".as_bytes());

const LDRLOADDLL_HASH: u32 = fnv1a_hash_32("LdrLoadDll".as_bytes());

#[inline(never)]
fn load() -> Result<(*mut u8, *mut u8)> {
	let rip: usize;
	#[cfg(target_arch = "x86_64")]
	unsafe {
		asm!("lea {rip}, [rip]", rip = out(reg) rip)
	};
	#[cfg(target_arch = "x86")]
	unsafe {
		asm!("lea {eip}, [eip]", rip = out(reg) rip)
	};
	let (pe_base, pe) = find_pe(rip)?;

	// Locate other important data structures
	let teb: *mut TEB;
	unsafe {
		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
		#[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
	}
	let teb = unsafe { &mut *teb };
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };

	let peb_ldr = unsafe { &*peb.Ldr };

	// Traverse loaded modules to find ntdll.dll
	let ntdll_base = find_loaded_module_by_hash(peb_ldr, NTDLL_HASH)?;
	let ntdll = PeHeaders::parse(ntdll_base)?;

	// Locate the export table for ntdll.dll
	let ntdll_export_table = ntdll.export_table_mem(ntdll_base)?;

	let syscall_table = syscall_table(&ntdll_export_table, ntdll_base);

	// Find some important syscall numbers
	let sys_no_zwflushinstructioncache =
		find_syscall_by_hash(&syscall_table, ZWFLUSHINSTRUCTIONCACHE_HASH)?;
	let sys_no_zwallocatevirtualmemory =
		find_syscall_by_hash(&syscall_table, ZWALLOCATEVIRTUALMEMORY_HASH)?;
	let sys_no_zwprotectvirtualmemory =
		find_syscall_by_hash(&syscall_table, ZWPROTECTVIRTUALMEMORY_HASH)?;

	let ldrloaddll = find_export_by_hash(&ntdll_export_table, ntdll_base, LDRLOADDLL_HASH)?;
	let ldrloaddll = unsafe {
		transmute::<
			_,
			unsafe extern "system" fn(
				DllPath: *const u16,
				DllCharacteristics: *const u32,
				DllName: *const UNICODE_STRING,
				DllHandle: *mut *mut u8,
			) -> i32,
		>(ldrloaddll)
	};

	// Allocate space to map the PE into
	let size_of_image = pe
		.nt_header
		.optional_header()
		.size_of_image
		.get(LittleEndian) as usize;

	let mut allocated_ptr = null_mut::<u8>();
	let mut region_size = size_of_image as usize;

	let nt_status = unsafe {
		syscall6(
			sys_no_zwallocatevirtualmemory,
			-1i64 as _,
			&mut allocated_ptr as *mut _ as _,
			0,
			&mut region_size as *mut _ as _,
			(MEM_RESERVE | MEM_COMMIT) as _,
			PAGE_READWRITE as _,
		)
	};
	if nt_status != STATUS_SUCCESS as _ {
		return Err(Error::Allocation);
	}

	if allocated_ptr.is_null() {
		return Err(Error::Allocation);
	}

	// Copy over header data
	let header_size = pe
		.nt_header
		.optional_header()
		.size_of_headers
		.get(LittleEndian) as _;
	simple_memcpy(allocated_ptr, pe_base, header_size);

	// Map sections
	pe.section_headers.iter().for_each(|section| {
		let dest = unsafe { allocated_ptr.add(section.virtual_address.get(LittleEndian) as _) };
		let src = unsafe { pe_base.add(section.pointer_to_raw_data.get(LittleEndian) as _) };
		let size = section.size_of_raw_data.get(LittleEndian) as _;
		simple_memcpy(dest, src, size);
	});

	// Process import table
	let import_table = pe.import_table_mem(allocated_ptr)?;
	for idt in import_table.import_descriptors {
		// Load the library
		let name_rva = idt.name.get(LittleEndian) as usize;
		let library_name = unsafe { allocated_ptr.add(name_rva) };

		// Load library if it is not already loaded and get the base
		let loaded_library_base = get_library_base(peb_ldr, library_name as _, ldrloaddll)?;

		// Find the exports of the loaded library
		let loaded_library = PeHeaders::parse(loaded_library_base)?;
		let loaded_library_exports = loaded_library.export_table_mem(loaded_library_base)?;

		let ilt_rva = idt.original_first_thunk.get(LittleEndian) as usize;
		let iat_rva = idt.first_thunk.get(LittleEndian) as usize;

		let mut ilt_ptr = unsafe { allocated_ptr.add(ilt_rva).cast::<ImageThunkData64>() };
		let mut iat_ptr = unsafe { allocated_ptr.add(iat_rva).cast::<usize>() };

		// Look through each entry in the ILT until we find a null entry
		while unsafe { ilt_ptr.read().raw() != 0 } {
			let ilt_entry = unsafe { ilt_ptr.read() };

			// Resolve the function VA - taking forwarding into account

			// First step - get an address from direct dependency
			let mut resolved_address = match ilt_entry.is_ordinal() {
				true => {
					// Load from ordinal
					let ordinal = ilt_entry.ordinal();

					// Find matching function in loaded library
					let export_rva = unsafe {
						*loaded_library_exports
							.address_table
							.get_unchecked(ordinal as usize)
					};

					unsafe { loaded_library_base.add(export_rva as _) }
				}
				false => {
					// Load from name
					let address_rva = ilt_entry.address() as _;

					// Get the name of the function
					let string_va = unsafe { allocated_ptr.add(address_rva).add(size_of::<u16>()) };
					let string = unsafe { CStr::from_ptr(string_va as _) };

					// Find matching function in loaded library
					find_export_by_ascii(&loaded_library_exports, loaded_library_base, string)?
				}
			};

			// Forwarding
			let mut current_export_start = loaded_library_exports.start_address;
			let mut current_export_end =
				unsafe { current_export_start.add(loaded_library_exports.size as _) };
			let function_va = loop {
				let mut buffer = [0u8; 64];

				if !(current_export_start <= resolved_address
					&& resolved_address < current_export_end)
				{
					// The pointer is not located in the exports section and therefore has no more forwarders
					break resolved_address;
				}

				// We have a pointer to a null-terminated string of the form "MYDLL.expfunc" or "MYDLL.#27"
				let string = unsafe { CStr::from_ptr(resolved_address as _) };
				let string = string.to_bytes_with_nul();

				// Copy string to buffer
				for i in 0..string.len() {
					unsafe {
						let c = *string.get_unchecked(i);
						*buffer.get_unchecked_mut(i) = c;
					}
				}

				// Give an extra 4 bytes for adding "dll\0"
				let working_buffer = unsafe { buffer.get_unchecked_mut(..string.len() + 4) };

				// Find the dot
				let dot_index = working_buffer
					.iter()
					.position(|&b| b == b'.')
					.ok_or(Error::SplitString)?;

				// Move things after the dot forwards
				for i in (dot_index + 1..working_buffer.len()).rev() {
					unsafe {
						let c = *working_buffer.get_unchecked(i);
						*working_buffer.get_unchecked_mut(i + 4) = c;
					};
				}

				// Write DLL
				unsafe {
					*working_buffer.get_unchecked_mut(dot_index + 1) = b'd';
					*working_buffer.get_unchecked_mut(dot_index + 2) = b'l';
					*working_buffer.get_unchecked_mut(dot_index + 3) = b'l';
					*working_buffer.get_unchecked_mut(dot_index + 4) = b'\0';
				}

				let (dll_name, rest) =
					unsafe { working_buffer.split_at_mut_unchecked(dot_index + 5) };

				// Load library if it is not already loaded and get the base
				let loaded_library_base = get_library_base(peb_ldr, dll_name.as_ptr(), ldrloaddll)?;

				// Find the exports of the loaded library
				let loaded_library = PeHeaders::parse(loaded_library_base)?;
				let loaded_library_exports =
					loaded_library.export_table_mem(loaded_library_base)?;

				// Set resolved address for next loop
				resolved_address = if unsafe { *rest.get_unchecked(0) } == b'#' {
					// Load from ordinal
					let number_string = unsafe { from_utf8_unchecked(rest.get_unchecked(1..)) };
					let ordinal =
						u16::from_str_radix(number_string, 10).map_err(|_| Error::ParseNumber)?;

					// Find matching function in loaded library
					let export_rva = unsafe {
						*loaded_library_exports
							.address_table
							.get_unchecked(ordinal as usize)
					};

					unsafe { loaded_library_base.add(export_rva as _) }
				}
				else {
					// Load from name

					// Get the name of the function
					let string = unsafe { CStr::from_ptr(rest.as_ptr() as _) };

					// Find matching function in loaded library
					find_export_by_ascii(&loaded_library_exports, loaded_library_base, string)?
				};

				// Set the new export range
				current_export_start = loaded_library_exports.start_address;
				current_export_end =
					unsafe { current_export_start.add(loaded_library_exports.size as _) };
			};

			// Write function VA into IAT
			unsafe { *iat_ptr = function_va as _ };

			// Advance to the next entry
			ilt_ptr = unsafe { ilt_ptr.add(1) };
			iat_ptr = unsafe { iat_ptr.add(1) };
		}
	}

	// Process relocations
	let image_base_in_file = pe.nt_header.optional_header().image_base();
	let calculated_offset = allocated_ptr as isize - image_base_in_file as isize;

	let relocations = unsafe {
		pe.data_directories
			.get_unchecked(IMAGE_DIRECTORY_ENTRY_BASERELOC)
	};

	// Iterate through the relocation table
	let reloc_start_address =
		unsafe { allocated_ptr.add(relocations.virtual_address.get(LittleEndian) as _) };
	let reloc_size_bytes = relocations.size.get(LittleEndian) as _;

	let mut reloc_byte_slice =
		unsafe { slice::from_raw_parts(reloc_start_address, reloc_size_bytes) };

	// Loop over relocation blocks - each has a 8 byte header
	while let &[a, b, c, d, e, f, g, h, ref rest @ ..] = reloc_byte_slice {
		let rva = u32::from_le_bytes([a, b, c, d]) as usize;
		let relocs_bytes = u32::from_le_bytes([e, f, g, h]) as usize - 8;

		let block_va = unsafe { allocated_ptr.add(rva) };

		// Loop over the relocations in this block
		let (mut relocs_slice, rest) = unsafe { rest.split_at_unchecked(relocs_bytes) };
		while let &[a, b, ref rest @ ..] = relocs_slice {
			let reloc = u16::from_le_bytes([a, b]);

			let reloc_type = (reloc & 0xf000) >> 0xc;
			let reloc_offset = reloc & 0x0fff;

			let reloc_va = unsafe { block_va.add(reloc_offset as _) };

			// Apply the relocation
			match reloc_type {
				IMAGE_REL_BASED_ABSOLUTE => (),
				IMAGE_REL_BASED_DIR64 => {
					let ptr = reloc_va as *mut u64;
					unsafe { *ptr = *ptr + calculated_offset as u64 };
				}
				IMAGE_REL_BASED_HIGHLOW => {
					let ptr = reloc_va as *mut u32;
					unsafe { *ptr = *ptr + calculated_offset as u32 };
				}
				_ => return Err(Error::RelocationType),
			}

			relocs_slice = rest;
		}

		reloc_byte_slice = rest;
	}

	// Set header permissions
	let base_address = allocated_ptr;
	let mut region_size = header_size;
	let mut old_permissions = u32::default();
	let nt_status = unsafe {
		syscall5(
			sys_no_zwprotectvirtualmemory,
			-1i64 as _,
			&base_address as *const _ as _,
			&mut region_size as *mut _ as _,
			PAGE_READONLY as _,
			&mut old_permissions as *mut _ as _,
		)
	};
	if nt_status != STATUS_SUCCESS as _ {
		return Err(Error::Protect);
	}

	// Set section permissions
	pe.section_headers.iter().try_for_each(|section| {
		let virtual_address =
			unsafe { allocated_ptr.add(section.virtual_address.get(LittleEndian) as _) };
		let virtual_size = section.virtual_size.get(LittleEndian);

		// Change permissions
		let characteristics = section.characteristics.get(LittleEndian);
		let r = characteristics & IMAGE_SCN_MEM_READ != 0;
		let w = characteristics & IMAGE_SCN_MEM_WRITE != 0;
		let x = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
		let new_permissions = match (r, w, x) {
			(false, false, false) => PAGE_NOACCESS,
			(true, false, false) => PAGE_READONLY,
			(false, true, false) => PAGE_WRITECOPY,
			(true, true, false) => PAGE_READWRITE,
			(false, false, true) => PAGE_EXECUTE,
			(true, false, true) => PAGE_EXECUTE_READ,
			(false, true, true) => PAGE_EXECUTE_WRITECOPY,
			(true, true, true) => PAGE_EXECUTE_READWRITE,
		};
		let base_address = virtual_address;
		let mut region_size = virtual_size;
		let mut old_permissions = u32::default();
		let nt_status = unsafe {
			syscall5(
				sys_no_zwprotectvirtualmemory,
				-1i64 as _,
				&base_address as *const _ as _,
				&mut region_size as *mut _ as _,
				new_permissions as _,
				&mut old_permissions as *mut _ as _,
			)
		};
		if nt_status != STATUS_SUCCESS as _ {
			return Err(Error::Protect);
		}
		Ok(())
	})?;

	let entry_point = unsafe {
		allocated_ptr.add(
			pe.nt_header
				.optional_header()
				.address_of_entry_point
				.get(LittleEndian) as _,
		)
	};

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing
	let nt_status = unsafe { syscall3(sys_no_zwflushinstructioncache, -1i64 as _, 0, 0) };
	if nt_status != STATUS_SUCCESS as _ {
		return Err(Error::Flush);
	}
	// unsafe { ntflushinstructioncache(-1 as _, null_mut(), 0) };

	Ok((allocated_ptr, entry_point))
}

#[inline(never)]
fn handle_error(error: Error) {
	#[cfg(feature = "debug")]
	{
		let error_code = error as u16;

		// Write error code to invalid address for rudimentary debugging
		unsafe { *(0xdeadbeefdeadbeef as *mut _) = error_code };
	}
}

#[no_mangle]
#[inline(never)]
pub extern "system" fn reflective_loader(reserved: usize) {
	match load() {
		Ok((allocated_ptr, entry_point)) => {
			// Call entry point
			let entry_point_callable = unsafe {
				transmute::<_, unsafe extern "system" fn(usize, u32, usize)>(entry_point)
			};

			unsafe { entry_point_callable(allocated_ptr as _, DLL_PROCESS_ATTACH, reserved) };
		}
		Err(e) => handle_error(e),
	}
}

#[no_mangle]
#[inline(never)]
pub extern "system" fn reflective_loader_wow64(reserved: usize) {
	unsafe {
		asm!(
			".code32",
			"push ebp",
			"mov ebp, esp",
			"and esp, 0xfffffff0",
			"push 0x33",
			"call 1f",
			"1:",
			"add dword ptr [esp], 5",
			"retf",
			".code64",
		);
		reflective_loader(reserved);
		asm!(
			".code64",
			"call 1f",
			"1:",
			"mov dword ptr [rsp + 4], 0x23",
			"add dword ptr [rsp], 0xd",
			"retf",
			".code32",
			"mov esp, ebp",
			"pop ebp",
			".code64",
		);
	}
}
