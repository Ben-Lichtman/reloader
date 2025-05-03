use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[repr(u16)]
#[derive(Debug, Error)]
pub enum Error {
	#[error("PE headers")]
	PeHeaders,
	#[error("Export table")]
	ExportTable,
	#[error("Import table")]
	ImportTable,
	#[error("Debug table")]
	DebugTable,
	#[error("TLS table")]
	TlsTable,
}
