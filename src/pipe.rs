//! The pipes `put --field-from-pipe` names: each opened, checked to be a
//! pipe before anything is read, and read to its end. Never a file: a value
//! in a file is a value in a temporary file.

use std::fs::File;

/// All that came through the pipe at `path`; `None` when the path is
/// missing, or anything but a pipe (nothing is then read), or the read fails.
pub fn read(path: &str) -> Option<Vec<u8>> {
    let mut file = open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).ok()?;
    Some(bytes)
}

/// `<(command)`'s `/dev/fd/N` (on Linux a link to `/proc/self/fd/N`), a FIFO
/// once the link is followed. Checked before it is opened, since opening a
/// FIFO no one writes to waits, and again on what was opened.
#[cfg(unix)]
fn open(path: &str) -> Option<File> {
    use std::os::unix::fs::FileTypeExt;
    let fifo = |meta: std::fs::Metadata| meta.file_type().is_fifo();
    if !fifo(std::fs::metadata(path).ok()?) {
        return None;
    }
    let file = File::open(path).ok()?;
    fifo(file.metadata().ok()?).then_some(file)
}

/// A named pipe, `\\.\pipe\<name>`: PowerShell has no `<(command)`.
#[cfg(windows)]
fn open(path: &str) -> Option<File> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    if !path.starts_with(r"\\.\pipe\") {
        return None;
    }
    let file = File::open(path).ok()?;
    // SAFETY: the handle is the open file's, alive for the call.
    let kind = unsafe { GetFileType(file.as_raw_handle()) };
    (kind == FILE_TYPE_PIPE).then_some(file)
}
