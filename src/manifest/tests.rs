// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;

fn seq(records: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.push(RECORD_SEPARATOR);
        out.extend_from_slice(r.as_bytes());
        out.push(b'\n');
    }
    out
}

const ROOT: &str = r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#;
const TRAILER: &str = r#"{"mediaType":"application/vnd.uapi.16.trailer"}"#;

#[test]
fn parses_a_manifest() {
    let hello = sha256::to_hex(&sha256::digest(b"hello"));
    let m = parse(&seq(&[
        ROOT,
        r#"{"mode":493,"name":"EFI","type":"dir","uid":0,"gid":0}"#,
        r#"{"name":"EFI/BOOT","type":"dir"}"#,
        &format!(
            r#"{{"mTimeNSec":1700000000000000000,"mode":420,"name":"EFI/BOOT/BOOTX64.EFI","sha256":"{}","size":5}}"#,
            hello
        ),
        r#"{"name":"empty","size":"0"}"#,
        r#"{"contents":[{"literal":"aGVs bG8="}],"name":"literal.txt","mode":"644"}"#,
        r#"{"contents":[{"literal":"aGVsbG8"}],"name":"link","type":"lnk"}"#,
        r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AAAA"}"#,
        r#"{"mediaType":"application/x-unknown","whatever":1}"#,
        TRAILER,
    ]))
    .unwrap();
    assert_eq!(m.entries.len(), 6);
    assert_eq!(m.entries[4].mode, Some(0o644));
    assert_eq!(m.signatures, 1);
    assert_eq!(m.root.inode_type, InodeType::Directory);
    let boot = &m.entries[2];
    assert_eq!(boot.name.as_deref(), Some("EFI/BOOT/BOOTX64.EFI"));
    assert_eq!(boot.size, Some(5));
    assert_eq!(boot.mtime(), Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)));
    assert!(!boot.is_read_only());
    assert!(boot.is_streamed());
    let empty = &m.entries[3];
    assert_eq!(empty.sha256, Some(sha256::EMPTY));
    let literal = &m.entries[4];
    assert_eq!(literal.contents[0].literal.as_deref(), Some(&b"hello"[..]));
    assert_eq!(literal.size, Some(5));
    assert!(!literal.is_streamed());
    assert_eq!(m.streamed_bytes().unwrap(), 5);
    assert_eq!(m.entries[5].inode_type, InodeType::Symlink);
}

#[test]
fn rejects_broken_manifests() {
    let cases: &[&[&str]] = &[
        &[],
        &[ROOT],
        &[r#"{"name":"x"}"#, TRAILER],
        &[ROOT, r#"{"name":"x"}"#],
        &[ROOT, TRAILER, r#"{"name":"x"}"#],
        &[
            ROOT,
            r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AA=="}"#,
            r#"{"name":"x"}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"/abs"}"#, TRAILER],
        &[ROOT, r#"{"name":"a/../b"}"#, TRAILER],
        &[ROOT, r#"{"name":"Uapi16Manifest"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","type":"weird"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","type":"dir","size":1,"inodeToken":1}"#, TRAILER],
        &[ROOT, r#"{"name":"x","type":"fifo","size":1}"#, TRAILER],
        &[ROOT, r#"{"name":"x","mode":420,"readOnly":true}"#, TRAILER],
        &[
            ROOT,
            r#"{"name":"x","size":3,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"name":"x","contents":[{"file":"a","literal":"AA=="}]}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"x","contents":[{"encoding":"identity"}]}"#, TRAILER],
        &[
            ROOT,
            r#"{"name":"x","size":5,"contents":[{"originalSize":4}]}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"x"}"#, r#"{"name":"x"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","mode":5000}"#, TRAILER],
        &[ROOT, r#"{"name":"x","mode":"9"}"#, TRAILER],
        &[
            r#"{"mediaType":"application/vnd.uapi.16.manifest","name":"x"}"#,
            TRAILER,
        ],
        // The rules systemd's reader applies on top.
        &[ROOT, r#"{"name":"x","uid":65535}"#, TRAILER],
        &[ROOT, r#"{"name":"x","mediaType":null}"#, TRAILER],
        &[ROOT, r#"{"name":"x","extendedAttributes":[]}"#, TRAILER],
        &[ROOT, r#"{"name":"x","extendedAttributes":{"user":{"a":"b"}}}"#, TRAILER],
        &[
            ROOT,
            r#"{"name":"x","extendedAttributes":{"user":{"":{"text":"b"}}}}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"name":"x","extendedAttributes":{"user":{"a":{"text":"b","base64":"Yg=="}}}}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"name":"x","extendedAttributes":{"user":{"a":{"base64":"!"}}}}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"x","userName":""}"#, TRAILER],
        &[ROOT, r#"{"name":"x","userName":"123"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","userName":"a:b"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","groupName":" g"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","gptUuid":"not-a-uuid"}"#, TRAILER],
        &[ROOT, r#"{"name":"x","gptUuid":"12345678\u00e9"}"#, TRAILER],
        &[
            ROOT,
            r#"{"name":"x","gptTypeUuid":"\u00e9\u00e9\u00e9\u00e9\u00e9"}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"name":"x","gptLabel":"0123456789012345678901234567890123456"}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"x","gptFlags":0,"gptFlagNoAuto":true}"#, TRAILER],
        &[
            ROOT,
            r#"{"mediaType":"application/vnd.uapi.16.signature","data":"AAAA"}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","key":"xyz"}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"!!"}"#,
            TRAILER,
        ],
        &[
            ROOT,
            r#"{"name":"a.txt","size":0}"#,
            r#"{"name":"A.TXT","size":0}"#,
            TRAILER,
        ],
    ];
    for records in cases {
        assert!(parse(&seq(records)).is_err(), "{:?} accepted", records);
    }
    let long = "x".repeat(256);
    assert!(parse(&seq(&[ROOT, &format!(r#"{{"name":"{}","size":0}}"#, long), TRAILER])).is_err());
    let contents = format!("[{}]", vec![r#"{"literal":"AA=="}"#; 257].join(","));
    assert!(parse(&seq(&[
        ROOT,
        &format!(r#"{{"name":"x","contents":{}}}"#, contents),
        TRAILER
    ]))
    .is_err());
    let contents = format!("[{}]", vec![r#"{"literal":"AA=="}"#; 256].join(","));
    assert!(parse(&seq(&[
        ROOT,
        &format!(r#"{{"name":"x","contents":{}}}"#, contents),
        TRAILER
    ]))
    .is_ok());
    // Records beyond the cap.
    let big = format!(r#"{{"name":"x","size":0,"pad":"{}"}}"#, "p".repeat(MAX_RECORD_SIZE));
    assert_eq!(parse(&seq(&[ROOT, &big, TRAILER])).unwrap_err().errno(), E2BIG);
    // No record separator at all.
    assert!(parse(ROOT.as_bytes()).is_err());
    // Whitespace-only records are fine, as long as it is ASCII whitespace.
    let mut bytes = seq(&[ROOT]);
    bytes.extend_from_slice(&[RECORD_SEPARATOR, b'\n', b' ']);
    bytes.extend_from_slice(&seq(&[TRAILER]));
    assert!(parse(&bytes).is_ok());
    let mut bytes = seq(&[ROOT]);
    bytes.push(RECORD_SEPARATOR);
    bytes.extend_from_slice("\u{2028}".as_bytes());
    bytes.extend_from_slice(&seq(&[TRAILER]));
    assert!(parse(&bytes).is_err());
    // The rules systemd relaxes are relaxed here too.
    let m = parse(&seq(&[
        ROOT,
        r#"{"name":"x","size":"5","sha256":"2cf2 4dba 5fb0 a30e 26e8 3b2a c5b9 e29e 1b16 1e5c 1fa7 425e 7304 3362 938b 9824","validUntilUSec":"18446744073709551615"}"#,
        r#"{"name":"y","size":0,"uid":4294967294,"userName":"Domain Users","gptUuid":"urn:uuid:4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709","gptLabel":"root","gptFlags":9223372036854775808,"gptFlagNoAuto":true,"extendedAttributes":{"user":{"a":{"text":"b"},"c":{"base64":"Yg=="}},"other":5}}"#,
        TRAILER,
    ]))
    .unwrap();
    assert_eq!(m.entries[0].size, Some(5));
    assert_eq!(m.entries[0].sha256, Some(sha256::digest(b"hello")));
    assert_eq!(m.entries[0].valid_until_usec, Some(u64::MAX));
}

#[test]
fn base64() {
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
    assert_eq!(base64_decode("").unwrap(), b"");
    assert_eq!(base64_decode("_-8=").unwrap(), [0xff, 0xef]);
    assert_eq!(base64_decode("aGVs\nbG8 =").unwrap(), b"hello");
    assert!(base64_decode("a").is_none());
    assert!(base64_decode("a=b=").is_none());
    assert!(base64_decode("!!!!").is_none());
}
