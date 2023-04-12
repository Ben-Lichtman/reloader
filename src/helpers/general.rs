use crate::error::{Error, Result};
use core::{
	arch::asm,
	ffi::CStr,
	mem::{transmute, MaybeUninit},
	ptr::null_mut,
	sync::atomic::{compiler_fence, Ordering},
};
use ntapi::{ntpebteb::TEB, winapi::shared::ntdef::LIST_ENTRY};
use objparse::PeHeaders;

pub struct LinkedListPointer(*mut LIST_ENTRY);

impl LinkedListPointer {
	pub fn new(start: *mut LIST_ENTRY) -> Self { Self(start) }

	pub fn next(&mut self) -> *mut LIST_ENTRY {
		let cur = self.0;
		self.0 = unsafe { (*self.0).Flink };
		cur
	}

	pub fn prev(&mut self) -> *mut LIST_ENTRY {
		let cur = self.0;
		self.0 = unsafe { (*self.0).Blink };
		cur
	}

	pub fn next_until(&mut self, finish: *mut LIST_ENTRY) -> Option<*mut LIST_ENTRY> {
		if self.0.is_null() {
			return None;
		}
		let cur = self.0;
		let next = unsafe { (*self.0).Flink };
		if next == finish {
			self.0 = null_mut();
		}
		else {
			self.0 = next;
		}
		Some(cur)
	}

	pub fn prev_until(&mut self, finish: *mut LIST_ENTRY) -> Option<*mut LIST_ENTRY> {
		if self.0.is_null() {
			return None;
		}
		let cur = self.0;
		let prev = unsafe { (*self.0).Blink };
		if prev == finish {
			self.0 = null_mut();
		}
		else {
			self.0 = prev;
		}
		Some(cur)
	}
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
pub fn simple_memcpy(dest: *mut u8, src: *mut u8, len: usize) {
	let n_bytes = len; // Iterate backwards to avoid optimizing..?
	for i in (0..n_bytes).rev() {
		compiler_fence(Ordering::Acquire);
		unsafe { *dest.add(i) = *src.add(i) };
	}
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn memset_uninit_array<T: Copy, const L: usize>(
	dest: &mut [MaybeUninit<T>; L],
	value: T,
) -> &mut [T; L] {
	let n_bytes = dest.len(); // Iterate backwards to avoid optimizing..?
	for i in (0..n_bytes).rev() {
		compiler_fence(Ordering::Acquire);
		unsafe { dest.get_unchecked_mut(i).write(value) };
	}
	unsafe { transmute::<_, &mut [T; L]>(dest) }
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
pub fn get_teb() -> *mut TEB {
	let teb: *mut TEB;
	unsafe {
		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
		#[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
	}
	teb
}

#[cfg_attr(feature = "debug", inline(never))]
pub fn find_pe_base(start: usize) -> Result<*mut u8> {
	let mut aligned = start & !0xfff;
	loop {
		if aligned == 0 {
			return Err(Error::SelfFind);
		}

		match unsafe { PeHeaders::parse(aligned as _) } {
			Ok(_) => break Ok(aligned as _),
			Err(_) => aligned -= 0x1000,
		}
	}
}
