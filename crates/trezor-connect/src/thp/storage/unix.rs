use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{AtFlags, CWD, Mode, OFlags, openat, renameat, unlinkat},
    process::geteuid,
};

use super::acl;

pub(super) struct SecureParent {
    directory: fs::File,
    file_name: OsString,
}

fn storage_parent(path: &Path) -> Result<PathBuf, io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if parent.is_absolute() {
        Ok(parent.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(parent))
    }
}

pub(super) fn open_secure_parent(path: &Path) -> Result<SecureParent, io::Error> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "storage path has no file name")
    })?;
    let parent_path = storage_parent(path)?;
    let created = match fs::metadata(&parent_path) {
        Ok(_) => false,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(&parent_path)?;
            true
        }
        Err(err) => return Err(err),
    };

    let directory = fs::File::from(
        openat(
            CWD,
            &parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let metadata = directory.metadata()?;
    if metadata.uid() != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory must be owned by the current user",
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory must not be writable by group or others",
        ));
    }
    if created {
        acl::clear(&directory)?;
    } else if acl::has_entries(&directory)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory must not have extended ACL entries",
        ));
    }

    Ok(SecureParent {
        directory,
        file_name: file_name.to_os_string(),
    })
}

fn validate_secure_file(file: &fs::File) -> Result<(), io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "storage path is not a regular file",
        ));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage file must be owned by the current user",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage file must not have multiple hard links",
        ));
    }
    Ok(())
}

pub(super) fn read_secure_file(path: &Path) -> Result<Option<Vec<u8>>, io::Error> {
    let parent = open_secure_parent(path)?;
    read_secure_file_from_parent(&parent)
}

pub(super) fn read_secure_file_from_parent(
    parent: &SecureParent,
) -> Result<Option<Vec<u8>>, io::Error> {
    let descriptor = match openat(
        &parent.directory,
        parent.file_name.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(err) => {
            let err = io::Error::from(err);
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(err);
        }
    };
    let mut file = fs::File::from(descriptor);
    validate_secure_file(&file)?;
    if acl::has_entries(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage file must not have extended ACL entries",
        ));
    }
    let mode = file.metadata()?.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage file must not be writable by group or others",
        ));
    }
    if mode & 0o077 != 0 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn write_secure_file(parent: &fs::File, file_name: &OsStr, data: &[u8]) -> Result<(), io::Error> {
    let descriptor = openat(
        parent,
        file_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let mut file = fs::File::from(descriptor);
    validate_secure_file(&file)?;
    acl::clear(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn atomic_write(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let parent = open_secure_parent(path)?;
    atomic_write_in_parent(&parent, data)
}

pub(super) fn atomic_write_in_parent(parent: &SecureParent, data: &[u8]) -> Result<(), io::Error> {
    let mut tmp_name = parent.file_name.clone();
    tmp_name.push(format!(".tmp-{:032x}", rand::random::<u128>()));

    if let Err(err) = write_secure_file(&parent.directory, &tmp_name, data) {
        let _ = unlinkat(&parent.directory, &tmp_name, AtFlags::empty());
        return Err(err);
    }
    if let Err(err) = renameat(
        &parent.directory,
        &tmp_name,
        &parent.directory,
        parent.file_name.as_os_str(),
    ) {
        let _ = unlinkat(&parent.directory, &tmp_name, AtFlags::empty());
        return Err(io::Error::from(err));
    }
    Ok(())
}
