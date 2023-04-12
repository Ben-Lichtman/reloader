pub type Result<T> = core::result::Result<T, Error>;

#[repr(u16)]
#[derive(Debug)]
pub enum Error {
	ObjParse,
	SelfFind,
	ModuleByHash,
	ModuleByAscii,
	ExportVaByHash,
	ExportVaByAscii,
	Allocation,
	Protect,
	Flush,
	RelocationType,
	SplitString,
	ParseNumber,
	SyscallNumber,
	LdrLoadDll,
}

impl From<objparse::error::Error> for Error {
	fn from(_value: objparse::error::Error) -> Self { Self::ObjParse }
}
