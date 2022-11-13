use crate::error::{Error, Result};
use core::{ffi::CStr, mem::size_of, slice};
use object::{
	pe::{
		self, ImageDataDirectory, ImageDebugDirectory, ImageDosHeader, ImageExportDirectory,
		ImageImportDescriptor, ImageSectionHeader, ImageTlsDirectory64,
		IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
		IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
	},
	read::pe::{ImageNtHeaders, ImageOptionalHeader},
	LittleEndian,
};

pub struct PeHeaders {
	pub dos_header: &'static mut ImageDosHeader,
	#[cfg(target_arch = "x86_64")]
	pub nt_header: &'static mut pe::ImageNtHeaders64,
	#[cfg(target_arch = "x86")]
	pub nt_header: &'static mut pe::ImageNtHeaders32,
	pub data_directories: &'static mut [ImageDataDirectory],
	pub section_headers: &'static mut [ImageSectionHeader],
}

impl PeHeaders {
	#[cfg_attr(feature = "debug", inline(never))]
	pub fn parse(address: *mut u8) -> Result<Self> {
		let dos_header_ptr = address;
		let dos_header = unsafe { &mut *dos_header_ptr.cast::<ImageDosHeader>() };
		if dos_header.e_magic.get(LittleEndian) != IMAGE_DOS_SIGNATURE {
			return Err(Error::PeHeaders);
		}
		let nt_header_offset = dos_header.nt_headers_offset() as usize;
		// Sanity check
		if nt_header_offset > 1024 {
			return Err(Error::PeHeaders);
		}
		let nt_header_ptr = unsafe { address.add(nt_header_offset) };
		#[cfg(target_arch = "x86_64")]
		let nt_header = unsafe { &mut *nt_header_ptr.cast::<pe::ImageNtHeaders64>() };
		#[cfg(target_arch = "x86")]
		let nt_header = unsafe { &mut *nt_header_ptr.cast::<ImageNtHeaders32>() };
		if nt_header.signature.get(LittleEndian) != IMAGE_NT_SIGNATURE {
			return Err(Error::PeHeaders);
		}
		if !nt_header.is_valid_optional_magic() {
			return Err(Error::PeHeaders);
		}
		#[cfg(target_arch = "x86_64")]
		let data_directories_ptr = unsafe { nt_header_ptr.add(size_of::<pe::ImageNtHeaders64>()) };
		#[cfg(target_arch = "x86")]
		let data_directories_ptr = unsafe { nt_header_ptr.add(size_of::<pe::ImageNtHeaders32>()) };
		let num_data_directories = nt_header.optional_header().number_of_rva_and_sizes() as _;
		let data_directories = unsafe {
			slice::from_raw_parts_mut(
				data_directories_ptr.cast::<ImageDataDirectory>(),
				num_data_directories,
			)
		};
		let section_headers_ptr = unsafe {
			data_directories_ptr.add(num_data_directories * size_of::<ImageDataDirectory>())
		};
		let num_section_headers = nt_header.file_header().number_of_sections.get(LittleEndian) as _;
		let section_headers = unsafe {
			slice::from_raw_parts_mut(
				section_headers_ptr.cast::<ImageSectionHeader>(),
				num_section_headers,
			)
		};

		Ok(Self {
			dos_header,
			nt_header,
			data_directories,
			section_headers,
		})
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn export_table_mem(&self, image_base: *mut u8) -> Result<ExportTable> {
		let export_table_data_dir = self
			.data_directories
			.get(IMAGE_DIRECTORY_ENTRY_EXPORT)
			.ok_or(Error::ExportTable)?;
		let export_table_rva = export_table_data_dir.virtual_address.get(LittleEndian);
		let export_table_ptr = unsafe { image_base.add(export_table_rva as _) };
		let export_table_size = export_table_data_dir.size.get(LittleEndian);
		Ok(ExportTable::parse(
			export_table_ptr,
			export_table_rva as _,
			export_table_size,
		))
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn import_table_mem(&self, image_base: *mut u8) -> Result<ImportTable> {
		let import_table_data_dir = self
			.data_directories
			.get(IMAGE_DIRECTORY_ENTRY_IMPORT)
			.ok_or(Error::ImportTable)?;
		let import_table_rva = import_table_data_dir.virtual_address.get(LittleEndian);
		let import_table_size = import_table_data_dir.size.get(LittleEndian);
		let import_table_ptr = unsafe { image_base.add(import_table_rva as _) };
		Ok(ImportTable::parse(import_table_ptr, import_table_size as _))
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn debug_table_mem(&self, image_base: *mut u8) -> Result<DebugTable> {
		let debug_table_data_dir = self
			.data_directories
			.get(IMAGE_DIRECTORY_ENTRY_DEBUG)
			.ok_or(Error::ImportTable)?;
		let debug_table_rva = debug_table_data_dir.virtual_address.get(LittleEndian);
		let debug_table_size = debug_table_data_dir.size.get(LittleEndian);
		let debug_table_ptr = unsafe { image_base.add(debug_table_rva as _) };
		Ok(DebugTable::parse(debug_table_ptr, debug_table_size as _))
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn tls_table_mem(&self, image_base: *mut u8) -> Result<Option<TlsDir>> {
		let tls_table_data_dir = self
			.data_directories
			.get(IMAGE_DIRECTORY_ENTRY_TLS)
			.ok_or(Error::ImportTable)?;
		let tls_table_rva = tls_table_data_dir.virtual_address.get(LittleEndian);
		let _tls_table_size = tls_table_data_dir.size.get(LittleEndian);
		let tls_table_ptr = unsafe { image_base.add(tls_table_rva as _) };
		Ok(TlsDir::parse(tls_table_ptr))
	}
}

pub struct ExportTable {
	pub export_directory: &'static mut ImageExportDirectory,
	pub address_table: &'static mut [u32],
	pub name_table: &'static mut [u32],
	pub ordinal_table: &'static mut [u16],
	pub start_address: *mut u8,
	pub size: u32,
}

impl ExportTable {
	#[cfg_attr(feature = "debug", inline(never))]
	pub fn parse(address: *mut u8, rva: usize, size: u32) -> Self {
		let export_directory_ptr = address;
		let export_directory = unsafe { &mut *export_directory_ptr.cast::<ImageExportDirectory>() };

		let address_table_ptr = unsafe {
			address
				.add(export_directory.address_of_functions.get(LittleEndian) as _)
				.wrapping_sub(rva)
				.cast::<u32>()
		};
		let address_table_len = export_directory.number_of_functions.get(LittleEndian) as _;
		let address_table =
			unsafe { slice::from_raw_parts_mut(address_table_ptr, address_table_len) };

		let name_table_ptr = unsafe {
			address
				.add(export_directory.address_of_names.get(LittleEndian) as _)
				.wrapping_sub(rva)
				.cast::<u32>()
		};
		let name_table_len = export_directory.number_of_names.get(LittleEndian) as _;
		let name_table = unsafe { slice::from_raw_parts_mut(name_table_ptr, name_table_len) };

		let ordinal_table_ptr = unsafe {
			address
				.add(export_directory.address_of_name_ordinals.get(LittleEndian) as _)
				.wrapping_sub(rva)
				.cast::<u16>()
		};
		let ordinal_table_len = export_directory.number_of_names.get(LittleEndian) as _;
		let ordinal_table =
			unsafe { slice::from_raw_parts_mut(ordinal_table_ptr, ordinal_table_len) };

		Self {
			export_directory,
			address_table,
			name_table,
			ordinal_table,
			start_address: address,
			size,
		}
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn iter_name_ord(&self) -> impl Iterator<Item = (u32, u16)> + '_ {
		self.name_table
			.iter()
			.copied()
			.zip(self.ordinal_table.iter().copied())
	}

	#[cfg_attr(feature = "debug", inline(never))]
	pub fn iter_string_addr(&self, image_base: *mut u8) -> impl Iterator<Item = (&CStr, *mut u8)> {
		self.iter_name_ord().map(move |(name_rva, ord)| {
			let string_ptr = unsafe { image_base.add(name_rva as _) };
			let string = unsafe { CStr::from_ptr(string_ptr as _) };
			let address_rva = unsafe { *self.address_table.get_unchecked(ord as usize) };
			let address = unsafe { image_base.add(address_rva as _) };
			(string, address)
		})
	}
}

pub struct ImportTable {
	pub import_descriptors: &'static mut [ImageImportDescriptor],
}

impl ImportTable {
	#[cfg_attr(feature = "debug", inline(never))]
	pub fn parse(address: *mut u8, size: usize) -> Self {
		let number_of_entries = size / size_of::<ImageImportDescriptor>() - 1;
		let import_descriptor_ptr = address.cast::<ImageImportDescriptor>();
		let import_descriptors =
			unsafe { slice::from_raw_parts_mut(import_descriptor_ptr, number_of_entries) };

		Self { import_descriptors }
	}
}

pub struct DebugTable {
	pub debug_descriptors: &'static mut [ImageDebugDirectory],
}

impl DebugTable {
	#[cfg_attr(feature = "debug", inline(never))]
	pub fn parse(address: *mut u8, size: usize) -> Self {
		let number_of_entries = size / size_of::<ImageDebugDirectory>() - 1;
		let debug_descriptor_ptr = address.cast::<ImageDebugDirectory>();
		let debug_descriptors =
			unsafe { slice::from_raw_parts_mut(debug_descriptor_ptr, number_of_entries) };

		Self { debug_descriptors }
	}
}

pub struct TlsDir {
	pub tls_dir: &'static mut ImageTlsDirectory64,
}

impl TlsDir {
	#[cfg_attr(feature = "debug", inline(never))]
	pub fn parse(address: *mut u8) -> Option<Self> {
		if address.is_null() {
			return None;
		}

		let tls_dir = unsafe { &mut *address.cast::<ImageTlsDirectory64>() };

		Some(Self { tls_dir })
	}
}
