use crate::{
	error::{Error, Result},
	syscall::{syscall3, syscall5, syscall6},
	SyscallNumbers,
};
use core::ptr::null_mut;
use windows_sys::Win32::{
	Foundation::{STATUS_SUCCESS, UNICODE_STRING},
	System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
};

#[cfg_attr(feature = "debug", inline(never))]
pub fn allocate_memory(syscall_numbers: &SyscallNumbers, size: usize) -> Result<*mut u8> {
	let mut allocated_ptr = null_mut::<u8>();
	let mut region_size = size;

	let nt_status = unsafe {
		syscall6(
			syscall_numbers.sys_no_zwallocatevirtualmemory,
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
	Ok(allocated_ptr)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn protect_memory(
	syscall_numbers: &SyscallNumbers,
	base: *mut u8,
	size: usize,
	protection: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS> {
	let base_address = base;
	let mut region_size = size;
	let mut old_permissions = u32::default();
	let nt_status = unsafe {
		syscall5(
			syscall_numbers.sys_no_zwprotectvirtualmemory,
			-1i64 as _,
			&base_address as *const _ as _,
			&mut region_size as *mut _ as _,
			protection as _,
			&mut old_permissions as *mut _ as _,
		)
	};
	if nt_status != STATUS_SUCCESS as _ {
		return Err(Error::Protect);
	}
	Ok(old_permissions)
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn flush_instruction_cache(syscall_numbers: &SyscallNumbers) -> Result<()> {
	let nt_status = unsafe {
		syscall3(
			syscall_numbers.sys_no_zwflushinstructioncache,
			-1i64 as _,
			0,
			0,
		)
	};
	if nt_status != STATUS_SUCCESS as _ {
		return Err(Error::Flush);
	}
	Ok(())
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn load_dll(
	ldrloaddll: unsafe extern "system" fn(
		*const u16,
		*const u32,
		*const UNICODE_STRING,
		*mut *mut u8,
	) -> i32,
	unicode_string: *const UNICODE_STRING,
) -> Result<*mut u8> {
	let mut module_handle = null_mut::<u8>();
	unsafe { ldrloaddll(null_mut(), null_mut(), unicode_string, &mut module_handle) };
	if module_handle.is_null() {
		return Err(Error::LdrLoadDll);
	}
	Ok(module_handle)
}
