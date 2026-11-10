// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: reading them and assembling a volume from one.
//!
//! A manifest is an RFC 7464 JSON text sequence: each object is preceded by
//! an ASCII record separator (0x1E). The first object describes the manifest
//! itself, file objects follow, then optional signature objects and finally
//! the trailer. Objects with unknown media types are skipped, as the
//! specification requires. The structural checks are the ones systemd's
//! reader applies.
//!
//! Signatures are recognised but not verified: that needs an X.509 stack.
//! Callers who need authenticated manifests must verify them before handing
//! them over.
//!
//! Assembling a volume turns `dir` objects into directories and `reg`
//! objects into files whose contents come from a [`ContentSource`]: either
//! the files next to the manifest, or one stream carrying the contents of
//! every file in manifest order. Everything FAT cannot store (symlinks,
//! device nodes, FIFOs, sockets) is refused unless the caller asks for it to
//! be skipped.

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use json::{Object, Value};

use crate::errno::*;
use crate::sha256::{self, DIGEST_SIZE};
use crate::volume::MAX_FILE_SIZE;
use crate::{Detail, ManifestProblem, Result, UnsupportedKind, ValidityProblem};

mod assemble;
mod fields;
mod generate;
#[cfg(test)]
mod tests;

pub use assemble::{AssembleOptions, AssembleReport, ContentSource, DirectorySource, StreamSource};
pub use fields::{base64_decode, valid_name};
pub use generate::generate;

use fields::{
    access_mode, boolean, check_extended_attributes, check_signature, fat_key, hash, string, uint, valid_gpt_label,
    valid_id128, valid_user_group_name,
};

/// `bail!` for a defect of the manifest itself, with the problem a client
/// is told about; the record and the object's name are filled in by the
/// reader.
macro_rules! malformed {
    ($problem:expr, $errno:expr, $($arg:tt)*) => {
        return Err($crate::err!($errno, $crate::manifest::malformed($problem), $($arg)*))
    };
}

/// The detail of a defect of the manifest itself.
pub(super) fn malformed(problem: ManifestProblem) -> Detail {
    Detail::Manifest {
        problem,
        record: None,
        name: None,
        field: None,
    }
}

/// [`malformed`] about one field.
pub(super) fn malformed_field(problem: ManifestProblem, field: &str) -> Detail {
    Detail::Manifest {
        problem,
        record: None,
        name: None,
        field: Some(field.to_string()),
    }
}

/// Media type of the leading object.
pub const MEDIA_TYPE: &str = "application/vnd.uapi.16.manifest";
/// Media type of signature objects.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.uapi.16.signature";
/// Media type of the trailer object.
pub const TRAILER_MEDIA_TYPE: &str = "application/vnd.uapi.16.trailer";
/// Name of a manifest stored inside the tree it describes.
pub const FILENAME: &str = "Uapi16Manifest";
/// Suffix of manifests stored next to what they describe.
pub const SUFFIX: &str = ".Uapi16Manifest";
/// Largest record accepted, the same cap as systemd's reader.
pub const MAX_RECORD_SIZE: usize = 4 * 1024 * 1024;
/// Largest number of `contents` entries per object, as in systemd.
pub const MAX_CONTENTS: usize = 256;
/// Longest path component accepted, Linux's NAME_MAX.
const NAME_MAX: usize = 255;
/// Longest name accepted, below Linux's PATH_MAX.
const PATH_MAX: usize = 4096;
/// Longest GPT partition label, in UTF-16 units.
const GPT_LABEL_MAX: usize = 36;
/// GPT partition flag bits `gptFlagNoAuto` and `gptFlagGrowFileSystem`
/// mirror.
const GPT_FLAG_NO_AUTO: u64 = 1 << 63;
const GPT_FLAG_GROWFS: u64 = 1 << 59;
/// The record separator starting every record.
pub const RECORD_SEPARATOR: u8 = 0x1E;

/// The inode type of a file object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeType {
    /// `reg`
    Regular,
    /// `dir`
    Directory,
    /// `lnk`
    Symlink,
    /// `fifo`
    Fifo,
    /// `chr`
    CharDevice,
    /// `blk`
    BlockDevice,
    /// `sock`
    Socket,
}

impl InodeType {
    fn parse(s: &str) -> Option<InodeType> {
        Some(match s {
            "reg" => InodeType::Regular,
            "dir" => InodeType::Directory,
            "lnk" => InodeType::Symlink,
            "fifo" => InodeType::Fifo,
            "chr" => InodeType::CharDevice,
            "blk" => InodeType::BlockDevice,
            "sock" => InodeType::Socket,
            _ => return None,
        })
    }

    /// The name used in manifests.
    pub fn as_str(self) -> &'static str {
        match self {
            InodeType::Regular => "reg",
            InodeType::Directory => "dir",
            InodeType::Symlink => "lnk",
            InodeType::Fifo => "fifo",
            InodeType::CharDevice => "chr",
            InodeType::BlockDevice => "blk",
            InodeType::Socket => "sock",
        }
    }
}

/// Where the data of a file object comes from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Contents {
    /// A path relative to the manifest.
    pub file: Option<String>,
    /// An http or https URL.
    pub url: Option<String>,
    /// The data itself.
    pub literal: Option<Vec<u8>>,
    /// HTTP content coding the data is stored in.
    pub encoding: Option<String>,
    /// Size of the encoded data.
    pub encoded_size: Option<u64>,
    /// SHA-256 of the encoded data.
    pub encoded_sha256: Option<[u8; DIGEST_SIZE]>,
    /// Size of the decoded data.
    pub original_size: Option<u64>,
    /// SHA-256 of the decoded data.
    pub original_sha256: Option<[u8; DIGEST_SIZE]>,
    /// Offset of the file's data inside the decoded data.
    pub offset: u64,
}

/// A file object. Fields this crate has no use for (ownership, extended
/// attributes, GPT metadata) are type checked and dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Relative, normalized path; None only for the leading object.
    pub name: Option<String>,
    /// The inode type.
    pub inode_type: InodeType,
    /// Size in bytes, when known.
    pub size: Option<u64>,
    /// Access mode bits.
    pub mode: Option<u32>,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_nsec: Option<u64>,
    /// Whether the file is read-only.
    pub read_only: Option<bool>,
    /// Hardlink group token, 0 or absent for none.
    pub inode_token: Option<u64>,
    /// Content sources.
    pub contents: Vec<Contents>,
    /// SHA-256 of the file's data.
    pub sha256: Option<[u8; DIGEST_SIZE]>,
    /// Start of the validity window in microseconds since the epoch.
    pub valid_since_usec: u64,
    /// End of the validity window, if any.
    pub valid_until_usec: Option<u64>,
    /// Whether the entry is revoked.
    pub revoked: bool,
}

impl Entry {
    /// The path of the entry inside a volume.
    pub fn path(&self) -> String {
        format!("/{}", self.name.as_deref().unwrap_or(""))
    }

    /// Checks the validity window and the revocation flag against `now`.
    pub fn check_validity(&self, now_usec: u64) -> Result<()> {
        let what = self.name.as_deref().unwrap_or("the manifest");
        let invalid = |problem: ValidityProblem| Detail::Validity {
            name: self.path(),
            problem,
        };
        if self.revoked {
            bail!(EKEYREVOKED, invalid(ValidityProblem::Revoked), "{} is revoked", what);
        }
        if now_usec < self.valid_since_usec {
            bail!(
                EKEYEXPIRED,
                invalid(ValidityProblem::NotYetValid),
                "{} is not valid yet",
                what
            );
        }
        if let Some(until) = self.valid_until_usec {
            if now_usec >= until {
                bail!(EKEYEXPIRED, invalid(ValidityProblem::Expired), "{} has expired", what);
            }
        }
        Ok(())
    }

    /// The modification time, if the manifest has one.
    pub fn mtime(&self) -> Option<SystemTime> {
        self.mtime_nsec
            .map(|n| UNIX_EPOCH + Duration::new(n / 1_000_000_000, (n % 1_000_000_000) as u32))
    }

    /// Whether the file is read-only according to `readOnly` or `mode`.
    pub fn is_read_only(&self) -> bool {
        match (self.read_only, self.mode) {
            (Some(r), _) => r,
            (None, Some(m)) => m & 0o222 == 0,
            (None, None) => false,
        }
    }

    /// The `contents` entry the file's data is taken from: the first one
    /// without an `encoding` or a `url`, which this crate does not handle.
    /// None means the data is the file of the object's own name next to the
    /// manifest. An entry whose every contents alternative needs an encoding
    /// or a URL is refused with EOPNOTSUPP.
    pub fn fat_contents(&self) -> Result<Option<&Contents>> {
        if self.contents.is_empty() {
            return Ok(None);
        }
        if let Some(c) = self.contents.iter().find(|c| c.encoding.is_none() && c.url.is_none()) {
            return Ok(Some(c));
        }
        let mut reasons = Vec::new();
        for c in &self.contents {
            if let Some(e) = &c.encoding {
                reasons.push(format!("'{}' encoding", e));
            } else if c.url.is_some() {
                reasons.push("a URL".to_string());
            }
        }
        reasons.sort();
        reasons.dedup();
        bail!(
            EOPNOTSUPP,
            Detail::Unsupported {
                name: Some(self.path()),
                what: UnsupportedKind::Transport,
                value: Some(reasons.join(" or ")),
            },
            "'{}' is only available through {}, which is not supported",
            self.path(),
            reasons.join(" or ")
        )
    }

    /// Whether the entry can be stored on FAT by this crate. Symlinks,
    /// device nodes, FIFOs and sockets cannot; neither can a directory that
    /// refers to a sub-manifest nor a file whose contents need decoding or
    /// fetching. All of them are refused with EOPNOTSUPP.
    pub fn check_supported(&self) -> Result<()> {
        self.storable().map(|_| ())
    }

    /// What the entry is to FAT, if it can be stored, see
    /// [`Entry::check_supported`].
    pub fn storable(&self) -> Result<Storable<'_>> {
        match self.inode_type {
            InodeType::Regular => self.fat_contents().map(Storable::File),
            InodeType::Directory => {
                if !self.contents.is_empty() || self.sha256.is_some() {
                    bail!(
                        EOPNOTSUPP,
                        Detail::Unsupported {
                            name: Some(self.path()),
                            what: UnsupportedKind::SubManifest,
                            value: None,
                        },
                        "'{}' refers to a sub-manifest, which is not supported",
                        self.path()
                    );
                }
                Ok(Storable::Directory)
            }
            other => bail!(
                EOPNOTSUPP,
                Detail::Unsupported {
                    name: Some(self.path()),
                    what: UnsupportedKind::InodeType,
                    value: Some(other.as_str().to_string()),
                },
                "'{}' is a {}, which FAT cannot store",
                self.path(),
                other.as_str()
            ),
        }
    }

    /// Whether the data comes from outside the manifest, i.e. from a
    /// [`ContentSource`] rather than from a literal. Entries this crate
    /// cannot store are not streamed either.
    pub fn is_streamed(&self) -> bool {
        self.inode_type == InodeType::Regular
            && matches!(self.fat_contents(), Ok(c) if c.is_none_or(|c| c.literal.is_none()))
    }
}

/// An entry as FAT stores it, see [`Entry::storable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storable<'a> {
    /// A regular file, with its contents if the manifest names any.
    File(Option<&'a Contents>),
    /// A directory.
    Directory,
}

/// A parsed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The leading object.
    pub root: Entry,
    /// The file objects, in manifest order.
    pub entries: Vec<Entry>,
    /// Number of signature objects seen. None of them was verified.
    pub signatures: usize,
}

/// Applies the empty-hash/zero-size rules: a known empty hash implies size
/// 0 and vice versa.
fn reconcile_hash_and_size(hash: &mut Option<[u8; DIGEST_SIZE]>, size: &mut Option<u64>, what: &str) -> Result<()> {
    match (*hash, *size) {
        (Some(h), Some(s)) if h == sha256::EMPTY && s != 0 => {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "sha256"),
                "{}: a zero hash with a non-zero size",
                what
            )
        }
        (Some(h), Some(0)) if h != sha256::EMPTY => {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "size"),
                "{}: a zero size with a non-zero hash",
                what
            )
        }
        (Some(h), None) if h == sha256::EMPTY => *size = Some(0),
        (None, Some(0)) => *hash = Some(sha256::EMPTY),
        _ => {}
    }
    Ok(())
}

fn parse_contents(v: &Value, what: &str) -> Result<Contents> {
    let o = v.as_object().ok_or_else(|| {
        err!(
            EBADMSG,
            malformed_field(ManifestProblem::Contents, "contents"),
            "{}: contents entry is not an object",
            what
        )
    })?;
    let mut c = Contents::default();
    for (key, value) in o.iter() {
        if value.is_null() {
            continue;
        }
        match key {
            "file" => {
                let f = string(value, "file")?;
                if !valid_name(f) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contents, "file"),
                        "{}: contents file reference '{}' is not a valid relative path",
                        what,
                        f
                    );
                }
                c.file = Some(f.to_string());
            }
            "url" => {
                let u = string(value, "url")?;
                if !(u.starts_with("http://") || u.starts_with("https://")) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contents, "url"),
                        "{}: contents URL '{}' is not http or https",
                        what,
                        u
                    );
                }
                c.url = Some(u.to_string());
            }
            "literal" => {
                c.literal = Some(base64_decode(string(value, "literal")?).ok_or_else(|| {
                    err!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contents, "literal"),
                        "{}: literal contents are not Base64",
                        what
                    )
                })?);
            }
            "encoding" => {
                let e = string(value, "encoding")?.to_ascii_lowercase();
                if e.is_empty() || e == "identity" {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contents, "encoding"),
                        "{}: encoding '{}' is not permitted",
                        what,
                        e
                    );
                }
                c.encoding = Some(e);
            }
            "encodedSize" => c.encoded_size = Some(uint(value, key)?),
            "encodedSha256" => c.encoded_sha256 = Some(hash(value, key)?),
            "originalSize" => c.original_size = Some(uint(value, key)?),
            "originalSha256" => c.original_sha256 = Some(hash(value, key)?),
            "offset" => c.offset = uint(value, key)?,
            _ => {}
        }
    }
    if [c.file.is_some(), c.url.is_some(), c.literal.is_some()]
        .into_iter()
        .filter(|&set| set)
        .count()
        > 1
    {
        bail!(
            EBADMSG,
            malformed(ManifestProblem::Contents),
            "{}: only one of file, url and literal may be set",
            what
        );
    }
    reconcile_hash_and_size(&mut c.encoded_sha256, &mut c.encoded_size, what)?;
    reconcile_hash_and_size(&mut c.original_sha256, &mut c.original_size, what)?;
    if c.encoding.is_none() {
        // Without an encoding the encoded and the original data are the same.
        match (c.encoded_size, c.original_size) {
            (Some(a), Some(b)) if a != b => bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "encodedSize"),
                "{}: encoded and original size differ without an encoding",
                what
            ),
            (Some(a), None) => c.original_size = Some(a),
            (None, Some(b)) => c.encoded_size = Some(b),
            _ => {}
        }
        match (c.encoded_sha256, c.original_sha256) {
            (Some(a), Some(b)) if a != b => bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "encodedSha256"),
                "{}: encoded and original hash differ without an encoding",
                what
            ),
            (Some(a), None) => c.original_sha256 = Some(a),
            (None, Some(b)) => c.encoded_sha256 = Some(b),
            _ => {}
        }
    }
    if let Some(literal) = &c.literal {
        if let Some(s) = c.encoded_size {
            if s != literal.len() as u64 {
                bail!(
                    EBADMSG,
                    malformed_field(ManifestProblem::Contradiction, "literal"),
                    "{}: literal contents are {} bytes, not {}",
                    what,
                    literal.len(),
                    s
                );
            }
        }
        c.encoded_size = Some(literal.len() as u64);
        if c.encoding.is_none() {
            c.original_size = c.encoded_size;
        }
    }
    if let Some(total) = c.original_size {
        if c.offset > total {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contents, "offset"),
                "{}: contents offset {} is beyond the data size {}",
                what,
                c.offset,
                total
            );
        }
    }
    Ok(c)
}

/// Parses one file object. `index` is its position in the manifest; 0 is
/// the leading object.
pub fn parse_entry(object: &Object, index: usize) -> Result<Entry> {
    let mut e = Entry {
        name: None,
        inode_type: InodeType::Regular,
        size: None,
        mode: None,
        mtime_nsec: None,
        read_only: None,
        inode_token: None,
        contents: Vec::new(),
        sha256: None,
        valid_since_usec: 0,
        valid_until_usec: None,
        revoked: false,
    };
    let mut inode_type = None;
    let mut media_type = None;
    let mut major_minor = false;
    let mut gpt = false;
    let mut gpt_disk = false;
    let mut gpt_flags = None;
    let mut gpt_no_auto = None;
    let mut gpt_growfs = None;
    let what = |e: &Entry| format!("manifest object {} ({})", index, e.name.as_deref().unwrap_or("root"));
    for (key, value) in object.iter() {
        if value.is_null() {
            continue;
        }
        match key {
            "name" => {
                let n = string(value, key)?;
                if !valid_name(n) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::InvalidName, "name"),
                        "manifest object {}: name '{}' is not a valid relative path",
                        index,
                        n
                    );
                }
                e.name = Some(n.to_string());
            }
            "mediaType" => media_type = Some(string(value, key)?.to_string()),
            "type" => {
                let t = string(value, key)?;
                inode_type = Some(InodeType::parse(t).ok_or_else(|| {
                    err!(
                        EBADMSG,
                        malformed_field(ManifestProblem::UnknownType, "type"),
                        "manifest object {}: unknown inode type '{}'",
                        index,
                        t
                    )
                })?);
            }
            "size" => e.size = Some(uint(value, key)?),
            "mode" => e.mode = Some(access_mode(value, key)?),
            "uid" | "gid" => {
                // 0xFFFF and 0xFFFFFFFF are the invalid IDs.
                let v = uint(value, key)?;
                if v >= 0xFFFF_FFFF || v == 0xFFFF {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::FieldRange, key),
                        "manifest object {}: {} {} is out of range",
                        index,
                        key,
                        v
                    );
                }
            }
            "userName" | "groupName" => {
                let n = string(value, key)?;
                if !valid_user_group_name(n) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::FieldType, key),
                        "manifest object {}: {} '{}' is not a valid name",
                        index,
                        key,
                        n
                    );
                }
            }
            "gptLabel" => {
                let l = string(value, key)?;
                if !valid_gpt_label(l) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::FieldType, "gptLabel"),
                        "manifest object {}: '{}' is not a valid GPT partition label",
                        index,
                        l
                    );
                }
                gpt = true;
            }
            "gptUuid" | "gptTypeUuid" | "gptDiskUuid" => {
                let id = string(value, key)?;
                if !valid_id128(id) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::FieldType, key),
                        "manifest object {}: {} '{}' is not a UUID",
                        index,
                        key,
                        id
                    );
                }
                if key == "gptDiskUuid" {
                    gpt_disk = true;
                } else {
                    gpt = true;
                }
            }
            "major" | "minor" => {
                uint(value, key)?;
                major_minor = true;
            }
            "gptFlags" => {
                gpt_flags = Some(uint(value, key)?);
                gpt = true;
            }
            "gptFlagNoAuto" => {
                gpt_no_auto = Some(boolean(value, key)?);
                gpt = true;
            }
            "gptFlagGrowFileSystem" => {
                gpt_growfs = Some(boolean(value, key)?);
                gpt = true;
            }
            "mTimeNSec" => e.mtime_nsec = Some(uint(value, key)?),
            "inodeToken" => e.inode_token = Some(uint(value, key)?),
            "extendedAttributes" => check_extended_attributes(value, &format!("manifest object {}", index))?,
            "readOnly" => e.read_only = Some(boolean(value, key)?),
            "contents" => {
                let items = value.as_array().ok_or_else(|| {
                    err!(
                        EBADMSG,
                        malformed_field(ManifestProblem::FieldType, "contents"),
                        "manifest field 'contents' is not an array"
                    )
                })?;
                if items.len() > MAX_CONTENTS {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contents, "contents"),
                        "manifest object {}: more than {} contents entries",
                        index,
                        MAX_CONTENTS
                    );
                }
                for item in items {
                    e.contents
                        .push(parse_contents(item, &format!("manifest object {}", index))?);
                }
            }
            "sha256" => e.sha256 = Some(hash(value, key)?),
            "validSinceUSec" => e.valid_since_usec = uint(value, key)?,
            "validUntilUSec" => e.valid_until_usec = Some(uint(value, key)?),
            "validity" => {
                // Unknown values are treated as "good", as the spec asks.
                e.revoked = string(value, key)? == "revoked";
            }
            _ => {}
        }
    }
    if let Some(mt) = &media_type {
        if mt != MEDIA_TYPE {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::MediaType, "mediaType"),
                "manifest object {} has unexpected media type '{}'",
                index,
                mt
            );
        }
    }
    if index == 0 {
        if media_type.is_none() {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::MediaType, "mediaType"),
                "the first manifest object does not carry the manifest media type"
            );
        }
        if e.name.is_some() {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::FirstHasName, "name"),
                "the first manifest object has a name"
            );
        }
        if !matches!(inode_type, None | Some(InodeType::Directory)) {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::FirstNotDirectory, "type"),
                "the first manifest object is not a directory"
            );
        }
        e.inode_type = InodeType::Directory;
    } else {
        if e.name.is_none() {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::NoName, "name"),
                "manifest object {} has no name",
                index
            );
        }
        e.inode_type = inode_type.unwrap_or(InodeType::Regular);
    }
    // Fields the inode type does not permit.
    let t = e.inode_type;
    let w = what(&e);
    if e.size.is_some() && !matches!(t, InodeType::Regular | InodeType::Symlink | InodeType::Directory) {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "size"),
            "{}: 'size' is not permitted on a {}",
            w,
            t.as_str()
        );
    }
    if major_minor && !matches!(t, InodeType::BlockDevice | InodeType::CharDevice) {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "major"),
            "{}: 'major' and 'minor' are not permitted on a {}",
            w,
            t.as_str()
        );
    }
    if e.mode.is_some() && t == InodeType::Symlink {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "mode"),
            "{}: 'mode' is not permitted on a symlink",
            w
        );
    }
    if matches!(e.inode_token, Some(tok) if tok != 0) && t == InodeType::Directory {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "inodeToken"),
            "{}: 'inodeToken' is not permitted on a directory",
            w
        );
    }
    if (!e.contents.is_empty() || e.sha256.is_some())
        && !matches!(t, InodeType::Regular | InodeType::Symlink | InodeType::Directory)
    {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "contents"),
            "{}: 'contents' and 'sha256' are not permitted on a {}",
            w,
            t.as_str()
        );
    }
    if gpt && t != InodeType::Regular {
        bail!(
            EBADMSG,
            malformed(ManifestProblem::FieldNotPermitted),
            "{}: GPT fields are only permitted on regular files",
            w
        );
    }
    if gpt_disk && index != 0 {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldNotPermitted, "gptDiskUuid"),
            "{}: 'gptDiskUuid' is only permitted on the first object",
            w
        );
    }
    if let (Some(ro), Some(mode)) = (e.read_only, e.mode) {
        if ro == (mode & 0o222 != 0) {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "readOnly"),
                "{}: 'readOnly' and 'mode' contradict each other",
                w
            );
        }
    }
    if let Some(flags) = gpt_flags {
        if gpt_no_auto.is_some_and(|b| b != (flags & GPT_FLAG_NO_AUTO != 0))
            || gpt_growfs.is_some_and(|b| b != (flags & GPT_FLAG_GROWFS != 0))
        {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Contradiction, "gptFlags"),
                "{}: 'gptFlags' and the 'gptFlag*' fields contradict each other",
                w
            );
        }
    }
    reconcile_hash_and_size(&mut e.sha256, &mut e.size, &w)?;
    // Sizes and hashes of contents and object must agree where they overlap.
    for c in &e.contents {
        match (e.size, c.original_size) {
            (Some(size), Some(total)) => {
                if c.offset.checked_add(size).is_none_or(|end| end > total) {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contradiction, "offset"),
                        "{}: offset {} plus size {} exceeds the contents size {}",
                        w,
                        c.offset,
                        size,
                        total
                    );
                }
            }
            (None, Some(total)) => e.size = Some(total - c.offset),
            _ => {}
        }
        if c.offset == 0 && e.size.is_some() && c.original_size == e.size {
            match (e.sha256, c.original_sha256) {
                (Some(a), Some(b)) if a != b => {
                    bail!(
                        EBADMSG,
                        malformed_field(ManifestProblem::Contradiction, "sha256"),
                        "{}: object and contents hashes differ",
                        w
                    )
                }
                (None, Some(b)) => e.sha256 = Some(b),
                _ => {}
            }
        }
    }
    if e.size.is_some_and(|s| s > MAX_FILE_SIZE) && t == InodeType::Regular {
        bail!(
            EFBIG,
            Detail::TooLarge {
                path: Some(e.path()),
                size: e.size.unwrap_or(0),
                maximum: MAX_FILE_SIZE,
            },
            "{}: {} bytes exceed what FAT32 can store",
            w,
            e.size.unwrap_or(0)
        );
    }
    Ok(e)
}

/// Splits JSON text sequence records off the front of `buffer`. Returns the
/// record text and the number of bytes consumed, or None if the buffer holds
/// no complete record yet (unless `eof` is set).
fn next_record(buffer: &[u8], eof: bool) -> Result<Option<(&str, usize)>> {
    let mut consumed = 0;
    loop {
        let rest = &buffer[consumed..];
        if rest.is_empty() {
            return Ok(None);
        }
        if rest[0] != RECORD_SEPARATOR {
            bail!(
                EBADMSG,
                malformed(ManifestProblem::RecordSeparator),
                "manifest record does not start with a record separator but with byte 0x{:02x}",
                rest[0]
            );
        }
        let body = &rest[1..];
        let end = match body.iter().position(|&b| b == RECORD_SEPARATOR) {
            Some(p) => p,
            None if eof => body.len(),
            None if body.len() > MAX_RECORD_SIZE => {
                bail!(
                    E2BIG,
                    malformed(ManifestProblem::RecordTooLarge),
                    "manifest record exceeds {} bytes",
                    MAX_RECORD_SIZE
                )
            }
            None => return Ok(None),
        };
        let record = &body[..end];
        if record.len() > MAX_RECORD_SIZE {
            bail!(
                E2BIG,
                malformed(ManifestProblem::RecordTooLarge),
                "manifest record exceeds {} bytes",
                MAX_RECORD_SIZE
            );
        }
        if record.contains(&0) {
            bail!(
                EBADMSG,
                malformed(ManifestProblem::NulByte),
                "manifest record contains a NUL byte"
            );
        }
        let text = std::str::from_utf8(record).map_err(|_| {
            err!(
                EBADMSG,
                malformed(ManifestProblem::NotUtf8),
                "manifest record is not UTF-8"
            )
        })?;
        consumed += 1 + end;
        if text.bytes().all(|b| b.is_ascii_whitespace()) {
            // Empty records are skipped, as RFC 7464 suggests. Only ASCII
            // whitespace counts as empty, like systemd's strstrip().
            continue;
        }
        return Ok(Some((text, consumed)));
    }
}

/// Reads a manifest.
pub fn read(reader: &mut dyn Read) -> Result<Manifest> {
    let mut buffer = Vec::new();
    let mut root = None;
    let mut entries: Vec<Entry> = Vec::new();
    // FAT folds case, so names are keyed by their folded form.
    let mut names: HashMap<Vec<u16>, usize> = HashMap::new();
    let mut signatures = 0;
    let mut trailer = false;
    let mut index = 0;
    let mut eof = false;
    // Records are consumed by moving `start`; the bytes before it are
    // dropped when more input is read, once per chunk and not once per
    // record.
    let mut start = 0;
    let mut chunk = vec![0u8; 65536];
    loop {
        let (text, consumed) = match next_record(&buffer[start..], eof).map_err(|e| e.in_record(index as u64, None))? {
            Some((t, c)) => (t.to_string(), c),
            None if eof => break,
            None => {
                buffer.drain(..start);
                start = 0;
                let n = crate::host::read_some(reader, &mut chunk)?;
                if n == 0 {
                    eof = true;
                } else {
                    buffer.extend_from_slice(&chunk[..n]);
                }
                continue;
            }
        };
        start += consumed;
        if trailer {
            malformed!(
                ManifestProblem::DataAfterTrailer,
                EBADMSG,
                "manifest contains data after the trailer object"
            );
        }
        let value = json::parse(&text).map_err(|e| {
            err!(
                EBADMSG,
                malformed(ManifestProblem::NotJson),
                "manifest record {} is not valid JSON: {}",
                index,
                e
            )
            .in_record(index as u64, None)
        })?;
        let Value::Object(object) = value else {
            malformed!(
                ManifestProblem::NotObject,
                EBADMSG,
                "manifest record {} is not a JSON object",
                index
            )
        };
        let media_type = match object.get("mediaType") {
            None => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => malformed!(
                ManifestProblem::MediaType,
                EBADMSG,
                "manifest object {} has a mediaType that is not a string",
                index
            ),
        };
        if index == 0 {
            if media_type != Some(MEDIA_TYPE) {
                malformed!(
                    ManifestProblem::MediaType,
                    EBADMSG,
                    "the first object of the manifest is not of the manifest media type"
                );
            }
        } else if let Some(mt) = media_type.filter(|&mt| mt != MEDIA_TYPE) {
            match mt {
                TRAILER_MEDIA_TYPE => trailer = true,
                SIGNATURE_MEDIA_TYPE => {
                    check_signature(&object, index).map_err(|e| e.in_record(index as u64, None))?;
                    signatures += 1;
                }
                _ => {}
            }
            index += 1;
            continue;
        }
        if signatures > 0 {
            malformed!(
                ManifestProblem::FileAfterSignature,
                EBADMSG,
                "manifest contains a file object after a signature object"
            );
        }
        let entry = parse_entry(&object, index)
            .map_err(|e| e.in_record(index as u64, object.get("name").and_then(Value::as_str)))?;
        if index == 0 {
            root = Some(entry);
        } else {
            let name = entry.name.as_deref().unwrap_or_default();
            if let Some(&earlier) = names.get(&fat_key(name)) {
                let other = entries[earlier].name.as_deref().unwrap_or_default();
                if other == name {
                    malformed!(
                        ManifestProblem::DuplicateName,
                        EBADMSG,
                        "manifest lists '{}' twice",
                        name
                    );
                }
                malformed!(
                    ManifestProblem::DuplicateName,
                    EEXIST,
                    "manifest lists '{}' and '{}', which FAT cannot tell apart",
                    other,
                    name
                );
            }
            names.insert(fat_key(name), entries.len());
            entries.push(entry);
        }
        index += 1;
    }
    let Some(root) = root else {
        malformed!(ManifestProblem::Empty, EBADMSG, "manifest contains no objects")
    };
    if !trailer {
        malformed!(
            ManifestProblem::NoTrailer,
            EBADMSG,
            "manifest lacks the trailer object, it is incomplete"
        );
    }
    Ok(Manifest {
        root,
        entries,
        signatures,
    })
}

/// Parses a manifest held in memory.
pub fn parse(bytes: &[u8]) -> Result<Manifest> {
    let mut slice = bytes;
    read(&mut slice)
}

impl Manifest {
    /// Fails with EOPNOTSUPP for the first entry this crate cannot store,
    /// see [`Entry::check_supported`]. Assembling without `skip_unsupported`
    /// would fail at that entry; checking first avoids formatting for
    /// nothing.
    pub fn check_supported(&self) -> Result<()> {
        self.entries.iter().try_for_each(Entry::check_supported)
    }

    /// Total size of the data a [`ContentSource`] has to deliver: the sizes
    /// of all regular files without literal contents, in manifest order.
    /// Every such file needs a known size. Entries that cannot be stored do
    /// not count, since they are skipped or stop the assembly.
    pub fn streamed_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for e in &self.entries {
            if e.is_streamed() {
                let size = e.size.ok_or_else(|| {
                    err!(
                        EINVAL,
                        Detail::Manifest {
                            problem: ManifestProblem::NoSize,
                            record: None,
                            name: Some(e.path()),
                            field: Some("size".into()),
                        },
                        "'{}' has no size, so its contents cannot be streamed",
                        e.path()
                    )
                })?;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| err!(EOVERFLOW, "total manifest size overflows"))?;
            }
        }
        Ok(total)
    }
}
