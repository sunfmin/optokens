//! Whether only its owner may read a file: the one check, by operating
//! system, behind `private`.

use crate::account::Fault;
use crate::refusal::Refusal;
use std::fs::{File, Metadata};
use std::path::Path;

/// Refused unless only `file`'s owner may read it: on Unix, its mode is
/// 0600; on Windows, its access list allows nobody but its owner, SYSTEM and
/// the Administrators group.
#[cfg(unix)]
pub fn private(_file: &File, meta: &Metadata, path: &Path) -> Result<(), Refusal> {
    use crate::refusal::quoted;
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o7777;
    if mode == 0o600 {
        return Ok(());
    }
    Err(Refusal::of(
        &Fault::TokenFileOpen,
        format!(
            "the token file `{}` has mode {mode:04o}, not 0600: others may read the token",
            path.display()
        ),
        format!("chmod 600 {}", quoted(path)),
    ))
}

#[cfg(windows)]
pub fn private(file: &File, _meta: &Metadata, path: &Path) -> Result<(), Refusal> {
    let others = windows::others(file).map_err(|e| {
        Refusal::of(
            &Fault::TokenFileOpen,
            format!(
                "cannot read the access list of the token file `{}`: {e}",
                path.display()
            ),
            format!(
                "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
                path.display()
            ),
        )
    })?;
    if others.is_empty() {
        return Ok(());
    }
    let removes: String = others
        .iter()
        .map(|sid| format!(" /remove \"*{sid}\""))
        .collect();
    Err(Refusal::of(
        &Fault::TokenFileOpen,
        format!(
            "the token file `{}` grants access to {}: only its owner, SYSTEM and the Administrators group may have it",
            path.display(),
            others.join(", ")
        ),
        format!(
            "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"{removes}",
            path.display()
        ),
    ))
}

#[cfg(not(any(unix, windows)))]
pub fn private(_file: &File, _meta: &Metadata, _path: &Path) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };

    /// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE`.
    const ALLOWED: u8 = 0;
    const DENIED: u8 = 1;

    /// The security descriptor `GetSecurityInfo` allocated, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by GetSecurityInfo, freed once.
            unsafe { LocalFree(self.0 as _) };
        }
    }

    /// Each entry of `file`'s access list that grants access to anyone but
    /// its owner, SYSTEM and the Administrators group, by its SID (an
    /// inherited entry too); a null list grants everyone.
    pub fn others(file: &File) -> Result<Vec<String>, String> {
        let (mut owner, mut dacl, mut sd): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) =
            (null_mut(), null_mut(), null_mut());
        // SAFETY: a valid open handle; the out pointers are written by the call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("GetSecurityInfo failed with error {status}"));
        }
        let _sd = Descriptor(sd);
        if dacl.is_null() {
            return Ok(vec!["Everyone (the file has no access list)".to_string()]);
        }
        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `dacl` is the list GetSecurityInfo returned; `size` is its class's struct.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err("GetAclInformation failed".to_string());
        }
        let mut others = Vec::new();
        for i in 0..size.AceCount {
            let mut ace = null_mut();
            // SAFETY: `i` is below the list's count.
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                return Err(format!("GetAce({i}) failed"));
            }
            // SAFETY: every entry starts with its header.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            // A deny entry takes access away; any other kind of grant is refused.
            if header.AceType == DENIED {
                continue;
            }
            if header.AceType != ALLOWED {
                others.push(format!("an entry of type {}", header.AceType));
                continue;
            }
            // SAFETY: an allowed entry is an ACCESS_ALLOWED_ACE, its SID in place at SidStart.
            let sid =
                unsafe { (&raw const (*(ace as *const ACCESS_ALLOWED_ACE)).SidStart) as PSID };
            // SAFETY: both SIDs are valid for the descriptor's life.
            let mine = unsafe {
                EqualSid(sid, owner) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            };
            if !mine {
                others.push(sid_string(sid));
            }
        }
        Ok(others)
    }

    fn sid_string(sid: PSID) -> String {
        let mut text = null_mut();
        // SAFETY: `sid` is valid; the call allocates `text`, freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return "an unnamed SID".to_string();
        }
        // SAFETY: a NUL-terminated wide string from the call.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `len` wide chars are there.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: allocated by ConvertSidToStringSidW, freed once.
        unsafe { LocalFree(text as _) };
        s
    }
}
