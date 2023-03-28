#![no_std]
#![feature(slice_split_at_unchecked)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(const_char_from_u32_unchecked)]

mod error;
mod function_wrappers;
mod helpers;
mod structures;
mod syscall;

use crate::{
	error::{Error, Result},
	function_wrappers::{allocate_memory, flush_instruction_cache, protect_memory},
	helpers::{
		general::{
			find_pe_base, fnv1a_hash_32, fnv1a_hash_32_wstr, get_ip, get_teb, memset_uninit_array,
			simple_memcpy,
		},
		library::{
			find_export_by_ascii, find_export_by_hash, find_loaded_module_by_hash, get_library_base,
		},
		syscall::{find_syscall_by_hash, gen_syscall_table, SYSCALL_TABLE_SIZE},
	},
	structures::PeHeaders,
};
use core::{
	arch::asm,
	ffi::CStr,
	mem::{size_of, transmute, MaybeUninit},
	ptr::{addr_of_mut, null_mut},
	slice,
	str::from_utf8_unchecked,
};
use ntapi::{
	ntpebteb::TEB,
	ntpsapi::PEB_LDR_DATA,
	winapi::um::winnt::{DLL_PROCESS_ATTACH, PAGE_NOACCESS},
};
use object::{
	pe::{
		self, ImageThunkData64, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_TLS,
		IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
		IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
	},
	read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData},
	LittleEndian,
};
use wchar::wch;
use windows_sys::Win32::{
	Foundation::UNICODE_STRING,
	System::{
		Memory::{
			PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
			PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
		},
		SystemServices::PIMAGE_TLS_CALLBACK,
	},
};

// Abusing fnv1a hash to find the strings we're looking for
// Can't just do a string comparison because the segments aren't properly loaded yet

const NTDLL_HASH: u32 = fnv1a_hash_32_wstr(wch!("ntdll.dll"));

const ZWFLUSHINSTRUCTIONCACHE_HASH: u32 = fnv1a_hash_32("ZwFlushInstructionCache".as_bytes());
const ZWALLOCATEVIRTUALMEMORY_HASH: u32 = fnv1a_hash_32("ZwAllocateVirtualMemory".as_bytes());
const ZWPROTECTVIRTUALMEMORY_HASH: u32 = fnv1a_hash_32("ZwProtectVirtualMemory".as_bytes());

const LDRLOADDLL_HASH: u32 = fnv1a_hash_32("LdrLoadDll".as_bytes());

const GET_TICK_COUNT: u32 = fnv1a_hash_32("NtGetTickCount".as_bytes());

pub struct SyscallNumbers {
	sys_no_zwallocatevirtualmemory: u32,
	sys_no_zwprotectvirtualmemory: u32,
	sys_no_zwflushinstructioncache: u32,
}

pub struct ImportantStructures {
	teb: *mut TEB,
	peb_ldr: *mut PEB_LDR_DATA,
	ntdll_base: *mut u8,
}

pub struct LoaderContext {
	syscall_numbers: SyscallNumbers,
	ldr_load_dll: unsafe extern "system" fn(
		*const u16,
		*const u32,
		*const UNICODE_STRING,
		*mut *mut u8,
	) -> i32,
	get_tick_count: unsafe extern "system" fn() -> u32,
}

#[no_mangle]
#[cfg_attr(feature = "debug", inline(never))]
pub extern "system" fn reflective_loader(reserved: usize) {
	match reflective_loader_impl(reserved, false) {
		Ok(x) => x,
		Err(e) => handle_error(e),
	}
}

#[no_mangle]
#[cfg_attr(feature = "debug", inline(never))]
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
		match reflective_loader_impl(reserved, true) {
			Ok(x) => x,
			Err(e) => handle_error(e),
		}
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

#[cfg_attr(feature = "debug", inline(never))]
fn handle_error(error: Error) -> ! {
	#[cfg(feature = "debug")]
	{
		let error_code = error as u16;

		// Write error code to invalid address for rudimentary debugging
		unsafe { *(0xdeadbeefdeadbeef as *mut _) = error_code };
	}
	panic!()
}

#[cfg_attr(feature = "debug", inline(never))]
fn reflective_loader_impl(reserved: usize, wow64: bool) -> Result<()> {
	// Find ourselves
	let pe_base = find_pe_base(get_ip())?;

	// Find global structures
	let important_structures = find_structures()?;

	// Get information needed for loading a DLL
	let context = get_context(important_structures.ntdll_base)?;

	if wow64 {
		fixup_wow64_pre(&important_structures, &context);
	}

	// Load ourself as a DLL
	let (allocated_ptr, size_of_image, entry_point) =
		load_dll(pe_base, important_structures.peb_ldr, &context)?;

	if wow64 {
		fixup_wow64_post(
			&important_structures,
			&context,
			allocated_ptr,
			size_of_image,
		);
	}

	// Call entry point
	let entry_point_callable =
		unsafe { transmute::<_, unsafe extern "system" fn(usize, u32, usize)>(entry_point) };

	unsafe { entry_point_callable(allocated_ptr as _, DLL_PROCESS_ATTACH, reserved) };

	Ok(())
}

#[cfg_attr(feature = "debug", inline(never))]
fn fixup_wow64_pre(important_structures: &ImportantStructures, context: &LoaderContext) {
	// The process state in 64 bit mode is totally broken, we need to get it to some barely-functional state - enough to load some dependency DLLs etc.
	// Some dependencies will conflict with the 32 bit environment, but we will just assume that everything is fine here.
	// Ideally we'd be reimplementing some actual NTDLL functionality rather than these easy hacks

	// Initialize thread activation context
	let tick_count = unsafe { (context.get_tick_count)() };
	let teb = unsafe { &mut (*important_structures.teb) };
	let context_stack = &mut teb.ActivationStack;
	context_stack.StackId = tick_count;
	context_stack.NextCookieSequenceNumber = 1;
	context_stack.Flags = 2;
	context_stack.ActiveFrame = null_mut();
	teb.ActivationContextStackPointer = context_stack;

	// Initialize TLS
	teb.ThreadLocalStoragePointer = addr_of_mut!(teb.ThreadLocalStoragePointer) as _;
}

#[cfg_attr(feature = "debug", inline(never))]
fn fixup_wow64_post(
	important_structures: &ImportantStructures,
	context: &LoaderContext,
	pe_base: *mut u8,
	allocated_size: usize,
) {
	// TODO
}

#[cfg_attr(feature = "debug", inline(never))]
fn find_structures() -> Result<ImportantStructures> {
	// Locate other important data structures
	let teb = get_teb();
	let peb = unsafe { (*teb).ProcessEnvironmentBlock };
	let peb_ldr = unsafe { (*peb).Ldr };

	// Traverse loaded modules to find ntdll.dll
	let ntdll_base = find_loaded_module_by_hash(peb_ldr, NTDLL_HASH)?;

	Ok(ImportantStructures {
		teb,
		peb_ldr,
		ntdll_base,
	})
}

#[cfg_attr(feature = "debug", inline(never))]
fn get_context(ntdll_base: *mut u8) -> Result<LoaderContext> {
	let ntdll = PeHeaders::parse(ntdll_base)?;

	// Locate the export table for ntdll.dll
	let ntdll_export_table = ntdll.export_table_mem(ntdll_base)?;

	// Create the syscall table
	let mut syscall_table = MaybeUninit::uninit_array::<SYSCALL_TABLE_SIZE>();
	let syscall_table = memset_uninit_array(&mut syscall_table, 0);
	gen_syscall_table(&ntdll_export_table, ntdll_base, syscall_table);

	// Find some important syscall numbers
	let sys_no_zwallocatevirtualmemory =
		find_syscall_by_hash(syscall_table, ZWALLOCATEVIRTUALMEMORY_HASH)?;
	let sys_no_zwprotectvirtualmemory =
		find_syscall_by_hash(syscall_table, ZWPROTECTVIRTUALMEMORY_HASH)?;
	let sys_no_zwflushinstructioncache =
		find_syscall_by_hash(syscall_table, ZWFLUSHINSTRUCTIONCACHE_HASH)?;

	let syscall_numbers = SyscallNumbers {
		sys_no_zwallocatevirtualmemory,
		sys_no_zwprotectvirtualmemory,
		sys_no_zwflushinstructioncache,
	};

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

	let get_tick_count = find_export_by_hash(&ntdll_export_table, ntdll_base, GET_TICK_COUNT)?;

	let context = LoaderContext {
		syscall_numbers,
		ldr_load_dll: ldrloaddll,
		get_tick_count: unsafe { transmute(get_tick_count) },
	};
	Ok(context)
}

#[cfg_attr(feature = "debug", inline(never))]
fn load_dll(
	pe_base: *mut u8,
	peb_ldr: *mut PEB_LDR_DATA,
	context: &LoaderContext,
) -> Result<(*mut u8, usize, *mut u8)> {
	let pe = PeHeaders::parse(pe_base)?;

	// Allocate space to map the PE into
	let size_of_image = pe
		.nt_header
		.optional_header()
		.size_of_image
		.get(LittleEndian) as usize;

	let allocated_ptr = allocate_memory(&context.syscall_numbers, size_of_image)?;

	let header_size = copy_header(allocated_ptr, &pe, pe_base);

	map_sections(allocated_ptr, &pe, pe_base);

	process_imports(allocated_ptr, &pe, peb_ldr, context)?;

	process_relocations(allocated_ptr, &pe)?;

	set_permissions(allocated_ptr, header_size, &pe, context)?;

	let entry_point = unsafe {
		allocated_ptr.add(
			pe.nt_header
				.optional_header()
				.address_of_entry_point
				.get(LittleEndian) as _,
		)
	};

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing
	flush_instruction_cache(&context.syscall_numbers)?;

	process_tls(allocated_ptr, &pe);

	Ok((allocated_ptr, size_of_image, entry_point))
}

#[cfg_attr(feature = "debug", inline(never))]
fn copy_header(dest: *mut u8, pe: &PeHeaders, pe_base: *mut u8) -> usize {
	// Copy over header data
	let header_size = pe
		.nt_header
		.optional_header()
		.size_of_headers
		.get(LittleEndian) as _;
	simple_memcpy(dest, pe_base, header_size);
	header_size
}

#[cfg_attr(feature = "debug", inline(never))]
fn map_sections(dest: *mut u8, pe: &PeHeaders, pe_base: *mut u8) {
	// Map sections
	pe.section_headers.iter().for_each(|section| {
		let dest = unsafe { dest.add(section.virtual_address.get(LittleEndian) as _) };
		let src = unsafe { pe_base.add(section.pointer_to_raw_data.get(LittleEndian) as _) };
		let size = section.size_of_raw_data.get(LittleEndian) as _;
		simple_memcpy(dest, src, size);
	});
}

#[cfg_attr(feature = "debug", inline(never))]
fn process_imports(
	dest: *mut u8,
	pe: &PeHeaders,
	peb_ldr: *mut PEB_LDR_DATA,
	context: &LoaderContext,
) -> Result<()> {
	// Process import table
	let import_table = pe.import_table_mem(dest)?;
	for idt in import_table.import_descriptors {
		// Load the library
		let name_rva = idt.name.get(LittleEndian) as usize;
		let library_name = unsafe { dest.add(name_rva) };

		// Load library if it is not already loaded and get the base
		let loaded_library_base = get_library_base(peb_ldr, library_name as _, context)?;

		// Find the exports of the loaded library
		let loaded_library = PeHeaders::parse(loaded_library_base)?;
		let loaded_library_exports = loaded_library.export_table_mem(loaded_library_base)?;

		let ilt_rva = idt.original_first_thunk.get(LittleEndian) as usize;
		let iat_rva = idt.first_thunk.get(LittleEndian) as usize;

		let mut ilt_ptr = unsafe { dest.add(ilt_rva).cast::<ImageThunkData64>() };
		let mut iat_ptr = unsafe { dest.add(iat_rva).cast::<usize>() };

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
					let string_va = unsafe { dest.add(address_rva).add(size_of::<u16>()) };
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
				let loaded_library_base = get_library_base(peb_ldr, dll_name.as_ptr(), context)?;

				// Find the exports of the loaded library
				let loaded_library = PeHeaders::parse(loaded_library_base)?;
				let loaded_library_exports =
					loaded_library.export_table_mem(loaded_library_base)?;

				// Set resolved address for next loop
				resolved_address = if unsafe { *rest.get_unchecked(0) } == b'#' {
					// Load from ordinal
					let number_string = unsafe { from_utf8_unchecked(rest.get_unchecked(1..)) };
					let ordinal = number_string
						.parse::<u16>()
						.map_err(|_| Error::ParseNumber)?;

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
	Ok(())
}

#[cfg_attr(feature = "debug", inline(never))]
fn process_relocations(dest: *mut u8, pe: &PeHeaders) -> Result<()> {
	// Process relocations
	let image_base_in_file = pe.nt_header.optional_header().image_base();
	let calculated_offset = dest as isize - image_base_in_file as isize;

	let relocations = unsafe {
		pe.data_directories
			.get_unchecked(IMAGE_DIRECTORY_ENTRY_BASERELOC)
	};

	// Iterate through the relocation table
	let reloc_start_address =
		unsafe { dest.add(relocations.virtual_address.get(LittleEndian) as _) };
	let reloc_size_bytes = relocations.size.get(LittleEndian) as _;

	let mut reloc_byte_slice =
		unsafe { slice::from_raw_parts(reloc_start_address, reloc_size_bytes) };

	// Loop over relocation blocks - each has a 8 byte header
	while let &[a, b, c, d, e, f, g, h, ref rest @ ..] = reloc_byte_slice {
		let rva = u32::from_le_bytes([a, b, c, d]) as usize;
		let relocs_bytes = u32::from_le_bytes([e, f, g, h]) as usize - 8;

		let block_va = unsafe { dest.add(rva) };

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
					unsafe { *ptr += calculated_offset as u64 };
				}
				IMAGE_REL_BASED_HIGHLOW => {
					let ptr = reloc_va as *mut u32;
					unsafe { *ptr += calculated_offset as u32 };
				}
				_ => return Err(Error::RelocationType),
			}

			relocs_slice = rest;
		}

		reloc_byte_slice = rest;
	}
	Ok(())
}

#[cfg_attr(feature = "debug", inline(never))]
fn set_permissions(
	dest: *mut u8,
	header_size: usize,
	pe: &PeHeaders,
	context: &LoaderContext,
) -> Result<()> {
	// Set header permissions
	protect_memory(&context.syscall_numbers, dest, header_size, PAGE_READONLY)?;

	// Set section permissions
	pe.section_headers.iter().try_for_each(|section| {
		let virtual_address = unsafe { dest.add(section.virtual_address.get(LittleEndian) as _) };
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
		protect_memory(
			&context.syscall_numbers,
			virtual_address,
			virtual_size as _,
			new_permissions,
		)?;
		Ok(())
	})?;
	Ok(())
}

#[cfg_attr(feature = "debug", inline(never))]
fn process_tls(dest: *mut u8, pe: &PeHeaders) {
	// Initialise TLS callbacks
	let tls_callbacks = unsafe { pe.data_directories.get_unchecked(IMAGE_DIRECTORY_ENTRY_TLS) };
	let tls_dir = unsafe { dest.add(tls_callbacks.virtual_address.get(LittleEndian) as _) };
	#[cfg(target_arch = "x86_64")]
	let tls_dir = unsafe { &*tls_dir.cast::<pe::ImageTlsDirectory64>() };
	#[cfg(target_arch = "x86")]
	let tls_dir = unsafe { &*tls_dir.cast::<pe::ImageTlsDirectory32>() };

	// Calling each TLS callback
	let mut callback_addr =
		tls_dir.address_of_call_backs.get(LittleEndian) as *const PIMAGE_TLS_CALLBACK;
	while let Some(callback) = unsafe { *callback_addr } {
		unsafe { callback(dest as _, DLL_PROCESS_ATTACH, null_mut()) };
		callback_addr = unsafe { callback_addr.add(1) };
	}
}
