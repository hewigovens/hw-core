use std::{fs::File, io};

pub(super) fn clear(_file: &File) -> Result<(), io::Error> {
    Ok(())
}

pub(super) fn has_entries(_file: &File) -> Result<bool, io::Error> {
    Ok(false)
}
