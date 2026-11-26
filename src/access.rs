//! Whether only its owner may read a file: the one check, by operating
//! system, behind `private`; and [`restrict`], which makes a file so.

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
    judge(path, windows::entries(file))
}

#[cfg(not(any(unix, windows)))]
pub fn private(_file: &File, _meta: &Metadata, _path: &Path) -> Result<(), Refusal> {
    Ok(())
}

/// Makes `file` readable by its owner alone, as [`private`] judges it: on
/// Unix mode 0600; on Windows a protected access list granting only its
/// owner, SYSTEM and the Administrators group.
#[cfg(unix)]
pub fn restrict(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn restrict(file: &File) -> std::io::Result<()> {
    windows::restrict(file).map_err(std::io::Error::other)
}

#[cfg(not(any(unix, windows)))]
pub fn restrict(_file: &File) -> std::io::Result<()> {
    Ok(())
}

/// One entry of a file's access list, as Windows reports it.
#[cfg_attr(not(windows), allow(dead_code))] // judged on every OS, read only on Windows
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Grants access to `sid`, which may be the file's owner, SYSTEM or the
    /// Administrators group.
    Allow {
        sid: String,
        owner: bool,
        system: bool,
        admins: bool,
    },
    /// Takes access away.
    Deny,
    /// A grant of another type (an object or a callback entry), by its type.
    Other(u8),
}

/// A Windows token file's access list judged: refused unless it grants
/// nobody but its owner, SYSTEM and the Administrators group. `None` is a
/// null list, which grants everyone; `Err`, a list that could not be read.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn judge(path: &Path, dacl: Result<Option<Vec<Entry>>, String>) -> Result<(), Refusal> {
    let strip = format!(
        "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
        path.display()
    );
    let others: Vec<String> = match dacl {
        Err(e) => {
            return Err(Refusal::of(
                &Fault::TokenFileOpen,
                format!(
                    "cannot read the access list of the token file `{}`: {e}",
                    path.display()
                ),
                strip,
            ));
        }
        Ok(None) => vec!["Everyone (the file has no access list)".to_string()],
        Ok(Some(entries)) => entries
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Allow {
                    sid,
                    owner,
                    system,
                    admins,
                } => (!(owner || system || admins)).then_some(sid),
                Entry::Deny => None,
                Entry::Other(kind) => Some(format!("an entry of type {kind}")),
            })
            .collect(),
    };
    if others.is_empty() {
        return Ok(());
    }
    let removes: String = others
        .iter()
        .filter(|o| o.starts_with("S-"))
        .map(|sid| format!(" /remove \"*{sid}\""))
        .collect();
    Err(Refusal::of(
        &Fault::TokenFileOpen,
        format!(
            "the token file `{}` grants access to {}: only its owner, SYSTEM and the Administrators group may have it",
            path.display(),
            others.join(", ")
        ),
        format!("{strip}{removes}"),
    ))
}

#[cfg(windows)]
mod windows {
    use super::Entry;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorDacl, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
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

    /// Every entry of `file`'s access list, inherited ones too; `None` for a
    /// null list.
    pub fn entries(file: &File) -> Result<Option<Vec<Entry>>, String> {
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
            return Ok(None);
        }
        let mut entries = Vec::new();
        // SAFETY: `dacl` is the list GetSecurityInfo returned; its header counts its entries.
        for i in 0..u32::from(unsafe { (*dacl).AceCount }) {
            let mut ace = null_mut();
            // SAFETY: `i` is below the list's count.
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                return Err(format!("GetAce({i}) failed"));
            }
            // SAFETY: every entry starts with its header.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            entries.push(match header.AceType {
                DENIED => Entry::Deny,
                ALLOWED => {
                    // SAFETY: an allowed entry is an ACCESS_ALLOWED_ACE, its SID in place at SidStart.
                    let sid = unsafe {
                        (&raw const (*(ace as *const ACCESS_ALLOWED_ACE)).SidStart) as PSID
                    };
                    // SAFETY: both SIDs are valid for the descriptor's life.
                    unsafe {
                        Entry::Allow {
                            sid: sid_string(sid),
                            owner: EqualSid(sid, owner) != 0,
                            system: IsWellKnownSid(sid, WinLocalSystemSid) != 0,
                            admins: IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0,
                        }
                    }
                }
                other => Entry::Other(other),
            });
        }
        Ok(Some(entries))
    }

    /// Replaces `file`'s access list by a protected one (nothing inherited)
    /// granting full control to its owner, SYSTEM and the Administrators group.
    pub fn restrict(file: &File) -> Result<(), String> {
        let (mut owner, mut sd): (PSID, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut());
        // SAFETY: a valid open handle; the out pointers are written by the call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("GetSecurityInfo failed with error {status}"));
        }
        let _owned = Descriptor(sd);
        // `owner` points into `sd`, alive until `_owned` drops.
        let sddl = format!("D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", sid_string(owner));
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut built: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated wide string; the call allocates `built`, freed by `_built`.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut built,
                null_mut(),
            )
        } == 0
        {
            return Err(format!("the access list `{sddl}` does not parse"));
        }
        let _built = Descriptor(built);
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        // SAFETY: `built` is a valid descriptor; the out pointers are written by the call.
        if unsafe { GetSecurityDescriptorDacl(built, &mut present, &mut dacl, &mut defaulted) } == 0
        {
            return Err("GetSecurityDescriptorDacl failed".to_string());
        }
        // SAFETY: a valid open handle and the list inside `built`.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("SetSecurityInfo failed with error {status}"));
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::{Entry, judge};
    use std::path::Path;

    fn allow(sid: &str, owner: bool, system: bool, admins: bool) -> Entry {
        Entry::Allow {
            sid: sid.into(),
            owner,
            system,
            admins,
        }
    }

    const FILE: &str = r"C:\Users\ci\AppData\Roaming\optokens\token";

    #[test]
    fn a_dacl_of_the_owner_system_and_administrators_alone_is_private() {
        let each_alone = vec![
            allow("S-1-5-21-1-1001", true, false, false),
            allow("S-1-5-18", false, true, false),
            allow("S-1-5-32-544", false, false, true),
            Entry::Deny,
        ];
        assert_eq!(judge(Path::new(FILE), Ok(Some(each_alone))), Ok(()));
    }

    #[test]
    fn any_other_grant_is_refused_naming_it_and_the_icacls_that_strips_it() {
        let dacl = vec![
            allow("S-1-5-21-1-1001", true, false, false),
            allow("S-1-5-32-545", false, false, false),
            Entry::Other(5),
        ];
        let refused = judge(Path::new(FILE), Ok(Some(dacl))).unwrap_err();
        assert_eq!(refused.kind, Some("token_file_open"));
        assert_eq!(
            refused.fault,
            format!(
                "the token file `{FILE}` grants access to S-1-5-32-545, an entry of type 5: only its owner, SYSTEM and the Administrators group may have it"
            )
        );
        assert_eq!(
            refused.fix,
            format!(
                "icacls \"{FILE}\" /inheritance:r /grant:r \"%USERNAME%:F\" /remove \"*S-1-5-32-545\""
            )
        );
    }

    #[test]
    fn a_null_or_unreadable_dacl_is_refused() {
        let null = judge(Path::new(FILE), Ok(None)).unwrap_err();
        assert!(null.fault.contains("grants access to Everyone"), "{null:?}");
        assert_eq!(
            null.fix,
            format!("icacls \"{FILE}\" /inheritance:r /grant:r \"%USERNAME%:F\"")
        );
        let unread = judge(Path::new(FILE), Err("error 5".into())).unwrap_err();
        assert_eq!(
            unread.fault,
            format!("cannot read the access list of the token file `{FILE}`: error 5")
        );
    }
}
