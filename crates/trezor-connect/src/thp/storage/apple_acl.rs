use std::{
    ffi::{c_int, c_void},
    fs::File,
    io,
    os::fd::AsRawFd,
    ptr,
};

type Acl = *mut c_void;
type AclEntry = *mut c_void;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: c_int = 0;

unsafe extern "C" {
    fn acl_free(object: *mut c_void) -> c_int;
    fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
    fn acl_init(count: c_int) -> Acl;
    fn acl_set_fd_np(fd: c_int, acl: Acl, acl_type: c_int) -> c_int;
}

pub(super) fn clear(file: &File) -> Result<(), io::Error> {
    // SAFETY: acl_init takes no pointers and its returned allocation is released below.
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the file descriptor and allocated ACL remain valid for this call.
    let result = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
    let error = (result != 0).then(io::Error::last_os_error);
    // SAFETY: acl was allocated by acl_init and has not previously been released.
    let free_result = unsafe { acl_free(acl) };
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Some(error) = error
        && error.kind() != io::ErrorKind::Unsupported
    {
        return Err(error);
    }
    Ok(())
}

pub(super) fn has_entries(file: &File) -> Result<bool, io::Error> {
    // SAFETY: acl_get_fd_np only borrows the valid file descriptor.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        ) {
            return Ok(false);
        }
        return Err(error);
    }

    let mut entry = ptr::null_mut();
    // SAFETY: acl is valid and entry points to writable storage for the borrowed entry.
    let result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let error = (result < 0).then(io::Error::last_os_error);
    // SAFETY: acl was allocated by acl_get_fd_np and has not previously been released.
    let free_result = unsafe { acl_free(acl) };
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Some(error) = error
        && error.kind() != io::ErrorKind::InvalidInput
    {
        return Err(error);
    }
    Ok(result == 0)
}
