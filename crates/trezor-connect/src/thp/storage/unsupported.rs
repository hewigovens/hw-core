use std::{io, path::Path};

const MESSAGE: &str = "secure file storage is supported only on Unix platforms";

pub(super) fn read_secure_file(_path: &Path) -> Result<Option<Vec<u8>>, io::Error> {
    Err(io::Error::new(io::ErrorKind::Unsupported, MESSAGE))
}

pub(super) fn atomic_write(_path: &Path, _data: &[u8]) -> Result<(), io::Error> {
    Err(io::Error::new(io::ErrorKind::Unsupported, MESSAGE))
}
