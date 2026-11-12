// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use crate::populate::CopyOptions;
use crate::progress::Progress;
use crate::test_util::{volume, TempDir, TempImage};
use crate::volume::Volume;
use crate::{ContentProblem, SourceProblem};
use std::os::fd::AsFd;
use std::path::Path;

/// A directory resolved once, the way the tool resolves the SOURCE of a
/// manifest.
fn dir_source(path: &Path) -> DirectorySource {
    DirectorySource::new(crate::host::open_dir(path).unwrap())
}

/// The manifest the generator writes for the tree at `path`.
fn generated(path: &Path) -> Vec<u8> {
    generate(crate::host::open_dir(path).unwrap().as_fd()).unwrap()
}

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
        r#"{"contents":[{"literal":"aGVsbG8="}],"name":"link","type":"lnk"}"#,
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
        &[
            ROOT,
            r#"{"name":"x","extendedAttributes":{"user":{"a":{"base64":"Yg"}}}}"#,
            TRAILER,
        ],
        &[ROOT, r#"{"name":"x","contents":[{"literal":"aGVsbG8"}]}"#, TRAILER],
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
            r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AA="}"#,
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

/// The test vectors of systemd's unbase64mem() in
/// src/test/test-hexdecoct.c: what it decodes and what it refuses.
#[test]
fn base64() {
    for (text, data) in [
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg==", "foob"),
        ("Zm9vYmE=", "fooba"),
        ("Zm9vYmFy", "foobar"),
        (" ", ""),
        (" \n\r ", ""),
        ("    Zg\n==       ", "f"),
        (" Zm 8=\r", "fo"),
        ("  Zm9\n\r\r\nv   ", "foo"),
        (" Z m9vYg==\n\r", "foob"),
        (" Zm 9vYmE=   ", "fooba"),
        ("   Z m9v    YmFy   ", "foobar"),
        ("aGVs\nbG8 =", "hello"),
    ] {
        assert_eq!(base64_decode(text).as_deref(), Some(data.as_bytes()), "{:?}", text);
    }
    for text in ["A", "A====", "AAB==", " A A A B = ", " Z m 8 = q u u x "] {
        assert_eq!(base64_decode(text), None, "{:?}", text);
    }
}

/// Both alphabets, in any mix, with the values systemd's unbase64char()
/// gives the digits, and its test of the two spellings of the same data.
#[test]
fn base64_alphabets() {
    assert_eq!(base64_decode("AZaz").unwrap(), [1, 150, 179]);
    assert_eq!(base64_decode("09+/").unwrap(), [211, 223, 191]);
    assert_eq!(base64_decode("09-_").unwrap(), [211, 223, 191]);
    assert_eq!(base64_decode("_-8=").unwrap(), [0xff, 0xef]);
    let plaintext: &[u8] = &[
        0xcc, 0xa1, 0x72, 0x22, 0xae, 0xda, 0x66, 0x7e, 0x04, 0xa6, 0xe0, 0x82, 0x9a, 0x97, 0x05, 0xf6, 0x33, 0xe0,
        0x0f, 0xc2, 0x45, 0x13, 0x58, 0x3f, 0xc5, 0xf4, 0xf4, 0x31, 0xab, 0x3c, 0x5f, 0x83, 0x34, 0x5b, 0x27, 0x32,
        0x8a, 0x04, 0x6c, 0x43, 0x82, 0x07, 0xe3, 0x2c, 0xac, 0xb9, 0xfb, 0xac, 0xd0, 0x03, 0x91, 0x42, 0xcb, 0xa4,
        0xde, 0x87, 0x86, 0x85, 0x10, 0xbb, 0xb7, 0x5b, 0x4b, 0xc8, 0xa0, 0xf4, 0x22, 0x1d, 0x15, 0x71, 0x87, 0x9d,
        0xbf, 0x9f, 0xa9, 0xf1, 0xee, 0xa2, 0xb6, 0xaa, 0xc8, 0xc3, 0x37, 0x9c, 0xbb, 0xdf, 0x3e, 0xac, 0xdc, 0x94,
        0x54, 0x38, 0x56, 0x07, 0x34, 0xb4, 0x3c, 0xcc, 0x31, 0x13,
    ];
    for text in [
        "zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g/xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5+p8e6itqrIwzecu98+rNyUVDhWBzS0PMwxEw==",
        "zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g_xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5-p8e6itqrIwzecu98-rNyUVDhWBzS0PMwxEw==",
    ] {
        assert_eq!(base64_decode(text).as_deref(), Some(plaintext));
    }
}

/// What systemd refuses: a last group without its padding, incomplete
/// padding, padding with nothing to pad, padding that leaves bits set,
/// anything after the padding, and any character that is not a digit,
/// "=" or one of space, tab, newline and carriage return.
#[test]
fn base64_refuses() {
    for text in [
        "Zg", "Zm8", "aGVsbG8", "Zg=", "Zm9v=", "Zm9v==", "=", "==", " = ", "Zh==", "Zm9=", "Zg==Zg==", "Zg== x",
        "Z=g=", "====", "Zm9\x0cv", "Zm9\x0bv", "!!!!", "Zm9v\0",
    ] {
        assert_eq!(base64_decode(text), None, "{:?}", text);
    }
}

/// Data of every length up to 300 bytes comes back from its padded
/// encoding broken into lines of any width, the way systemd's
/// base64mem_full() writes it.
#[test]
fn base64_round_trip() {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut x = 1u32;
    for len in 0..300usize {
        let data: Vec<u8> = (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect();
        let mut text = Vec::new();
        for chunk in data.chunks(3) {
            let n = chunk.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
            for i in 0..4 {
                let digit = DIGITS[((n >> (18 - 6 * i)) & 63) as usize];
                text.push(if i <= chunk.len() { digit } else { b'=' });
            }
        }
        let mut lines = Vec::new();
        for line in text.chunks(1 + len % 77) {
            lines.extend_from_slice(line);
            lines.push(b'\n');
        }
        let decoded = base64_decode(std::str::from_utf8(&lines).unwrap());
        assert_eq!(decoded.as_deref(), Some(&data[..]), "{} bytes", len);
    }
}

fn manifest_with_tree() -> (Manifest, Vec<u8>) {
    let a = b"first file".to_vec();
    let b = vec![7u8; 5000];
    let m = parse(&seq(&[
        ROOT,
        r#"{"mTimeNSec":1700000000000000000,"name":"EFI","type":"dir"}"#,
        &format!(
            r#"{{"mTimeNSec":1700000001000000000,"name":"EFI/a.txt","sha256":"{}","size":{}}}"#,
            sha256::to_hex(&sha256::digest(&a)),
            a.len()
        ),
        &format!(
            r#"{{"mode":292,"name":"EFI/Linux/b.efi","sha256":"{}","size":{}}}"#,
            sha256::to_hex(&sha256::digest(&b)),
            b.len()
        ),
        r#"{"contents":[{"literal":"aGVsbG8="}],"name":"literal.txt","size":5}"#,
        TRAILER,
    ]))
    .unwrap();
    let mut blob = a;
    blob.extend(b);
    (m, blob)
}

#[test]
fn assembles_from_a_stream() {
    let (m, blob) = manifest_with_tree();
    assert_eq!(m.streamed_bytes().unwrap(), blob.len() as u64);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut reader: &[u8] = &blob;
    let report = v
        .assemble(&m, &mut StreamSource::new(&mut reader), &AssembleOptions::default())
        .unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (3, 1, 5015));
    assert_eq!(
        v.metadata("/EFI/a.txt").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
    let b = v.metadata("/EFI/Linux/b.efi").unwrap();
    assert_eq!(b.size, 5000);
    assert_eq!(
        b.attributes & crate::dirent::ATTR_READ_ONLY,
        crate::dirent::ATTR_READ_ONLY
    );
    // Implicitly created directories get the default time, clamped to
    // the FAT epoch.
    assert_eq!(
        v.metadata("/EFI/Linux").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(crate::time::FAT_EPOCH as u64)
    );
    let mut back = String::new();
    v.open_file("/literal.txt").unwrap().read_to_string(&mut back).unwrap();
    assert_eq!(back, "hello");

    // A short stream fails at the file it runs out in and leaves no
    // trace of it. The files before it are complete.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut short: &[u8] = &blob[..100];
    assert_eq!(
        v.assemble(&m, &mut StreamSource::new(&mut short), &AssembleOptions::default())
            .unwrap_err()
            .errno(),
        EBADMSG
    );
    assert!(v.metadata("/EFI/Linux/b.efi").is_err());
    assert_eq!(v.metadata("/EFI/a.txt").unwrap().size, 10);

    // A stream that goes on after the last file fails at that file, which
    // got more than the manifest says. It is not stored either.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let long_blob = [&blob[..], b"more"].concat();
    let mut long: &[u8] = &long_blob;
    let e = v
        .assemble(&m, &mut StreamSource::new(&mut long), &AssembleOptions::default())
        .unwrap_err();
    assert_eq!(e.errno(), EBADMSG);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Content {
                problem: ContentProblem::Size,
                size: None,
                expected: Some(5000),
                ..
            })
        ),
        "{:?}",
        e
    );
    assert!(v.metadata("/EFI/Linux/b.efi").is_err());
    assert_eq!(v.metadata("/EFI/a.txt").unwrap().size, 10);

    // A corrupted stream fails the hash check. The file it was about to
    // replace survives untouched.
    let mut bad = blob.clone();
    bad[0] ^= 1;
    let mut bad_reader: &[u8] = &bad;
    let e = v
        .assemble(&m, &mut StreamSource::new(&mut bad_reader), &AssembleOptions::default())
        .unwrap_err();
    assert!(e.message().contains("hash"), "{}", e);
    let mut back = String::new();
    v.open_file("/EFI/a.txt").unwrap().read_to_string(&mut back).unwrap();
    assert_eq!(back, "first file");

    // On a fresh volume the failed file leaves nothing behind.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut bad_reader: &[u8] = &bad;
    v.assemble(&m, &mut StreamSource::new(&mut bad_reader), &AssembleOptions::default())
        .unwrap_err();
    assert!(v.metadata("/EFI/a.txt").is_err());
    assert!(v.metadata("/EFI").is_ok());
}

#[test]
fn assembles_from_a_directory() {
    let tmp = TempDir::new("manifest");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("EFI/Linux")).unwrap();
    std::fs::write(dir.join("EFI/a.txt"), b"first file").unwrap();
    std::fs::write(dir.join("EFI/Linux/b.efi"), vec![7u8; 5000]).unwrap();
    let (m, _) = manifest_with_tree();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let report = v
        .assemble(&m, &mut dir_source(&dir), &AssembleOptions::default())
        .unwrap();
    assert_eq!(report.files, 3);

    // The generator produces a manifest the reader accepts and the
    // planner and assembler agree on.
    let generated = generated(&dir);
    let g = parse(&generated).unwrap();
    assert_eq!(
        g.entries.iter().filter_map(|e| e.name.clone()).collect::<Vec<_>>(),
        vec!["EFI", "EFI/Linux", "EFI/Linux/b.efi", "EFI/a.txt"]
    );
    let mut plan = crate::plan::Plan::new(crate::plan::PlanOptions {
        allow_small: true,
        cluster_size: Some(512),
        ..crate::plan::PlanOptions::new(512)
    });
    assert!(plan.add_manifest(&g).unwrap().is_empty());
    let est = plan.estimate().unwrap();
    let img = TempImage::new(est.size());
    let mut o = crate::format::FormatOptions {
        allow_small: true,
        ..Default::default()
    };
    est.apply(&mut o);
    crate::format::format(&img.device(), &o).unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    v.assemble(&g, &mut dir_source(&dir), &AssembleOptions::default())
        .unwrap();
    assert_eq!(v.free_clusters(), 0);
}

#[test]
fn unsupported_entries() {
    let hello = sha256::to_hex(&sha256::digest(b"hello"));
    let m = parse(&seq(&[
        ROOT,
        r#"{"name":"a/b/link","type":"lnk","contents":[{"literal":"eA=="}]}"#,
        r#"{"name":"encoded","size":5,"contents":[{"literal":"H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==","encoding":"gzip"}]}"#,
        r#"{"name":"remote","size":5,"contents":[{"url":"https://example.com/x"}]}"#,
        &format!(r#"{{"name":"sub","type":"dir","sha256":"{}","size":5}}"#, hello),
        r#"{"name":"ok","size":0}"#,
        TRAILER,
    ]))
    .unwrap();
    let unsupported: Vec<String> = m
        .entries
        .iter()
        .filter(|e| e.check_supported().is_err())
        .map(|e| e.name.clone().unwrap())
        .collect();
    assert_eq!(unsupported, vec!["a/b/link", "encoded", "remote", "sub"]);
    assert_eq!(m.check_supported().unwrap_err().errno(), EOPNOTSUPP);
    assert_eq!(m.streamed_bytes().unwrap(), 0);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut empty: &[u8] = &[];
    let e = v
        .assemble(&m, &mut StreamSource::new(&mut empty), &AssembleOptions::default())
        .unwrap_err();
    assert_eq!(e.errno(), EOPNOTSUPP);
    // Nothing was created for the entry that failed, not even parents.
    assert_eq!(v.read_dir("/").unwrap().len(), 0);
    let r = v
        .assemble(
            &m,
            &mut StreamSource::new(&mut empty),
            &AssembleOptions {
                skip_unsupported: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(r.skipped, unsupported);
    assert_eq!((r.files, r.directories), (1, 0));
    assert_eq!(v.metadata("/a").unwrap_err().errno(), ENOENT);
    // The planner skips the same entries.
    let mut plan = crate::plan::Plan::new(crate::plan::PlanOptions {
        allow_small: true,
        ..crate::plan::PlanOptions::new(512)
    });
    assert_eq!(plan.add_manifest(&m).unwrap(), unsupported);
}

#[test]
fn contents_are_chosen_by_what_can_be_used() {
    let hello = sha256::to_hex(&sha256::digest(b"hello"));
    let m = parse(&seq(&[
        ROOT,
        // A URL first, then an encoded literal, then plain data.
        &format!(r#"{{"name":"x","size":5,"sha256":"{}","contents":[{{"url":"https://example.com/x"}},{{"literal":"AAAA","encoding":"gzip"}},{{"literal":"aGVsbG8="}}]}}"#, hello),
        // A URL with a file as the alternative is read from the source.
        &format!(r#"{{"name":"y","size":5,"sha256":"{}","contents":[{{"url":"https://example.com/y"}},{{"file":"data/y.bin"}}]}}"#, hello),
        TRAILER,
    ]))
    .unwrap();
    assert_eq!(
        m.entries[0].fat_contents().unwrap().unwrap().literal.as_deref(),
        Some(&b"hello"[..])
    );
    assert!(!m.entries[0].is_streamed());
    assert_eq!(
        m.entries[1].fat_contents().unwrap().unwrap().file.as_deref(),
        Some("data/y.bin")
    );
    assert!(m.entries[1].is_streamed());
    let tmp = TempDir::new("manifest-contents");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data/y.bin"), b"hello").unwrap();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let r = v
        .assemble(&m, &mut dir_source(&dir), &AssembleOptions::default())
        .unwrap();
    assert_eq!((r.files, r.bytes), (2, 10));
    for name in ["/x", "/y"] {
        let mut back = String::new();
        v.open_file(name).unwrap().read_to_string(&mut back).unwrap();
        assert_eq!(back, "hello");
    }
}

/// A file the manifest takes whole has exactly the size the manifest gives.
/// One that grew since the manifest was written fails like one that shrank,
/// when the source is verified and again while it is copied. A part of a
/// file, at an offset or out of a larger originalSize, only has to fit.
#[test]
fn whole_files_have_the_size_of_the_manifest() {
    let tmp = TempDir::new("manifest-sizes");
    let dir = tmp.path().to_path_buf();
    std::fs::write(dir.join("a"), b"hello world").unwrap();
    let hello = sha256::to_hex(&sha256::digest(b"hello"));
    let world = sha256::to_hex(&sha256::digest(b"world"));
    // The manifest was written when `a` held "hello". The file is found by
    // the entry's name or through a file reference.
    for record in [
        format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, hello),
        format!(
            r#"{{"name":"b","size":5,"sha256":"{}","contents":[{{"file":"a"}}]}}"#,
            hello
        ),
    ] {
        let m = parse(&seq(&[ROOT, &record, TRAILER])).unwrap();
        let e = dir_source(&dir).verify(&m).unwrap_err();
        assert_eq!(e.errno(), EBADMSG);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Source {
                    problem: SourceProblem::Size,
                    size: Some(11),
                    expected: Some(5),
                    ..
                })
            ),
            "{:?}",
            e
        );
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = v
            .assemble(&m, &mut dir_source(&dir), &AssembleOptions::default())
            .unwrap_err();
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Content {
                    problem: ContentProblem::Size,
                    size: Some(11),
                    expected: Some(5),
                    ..
                })
            ),
            "{:?}",
            e
        );
        assert!(v.read_dir("/").unwrap().is_empty());
    }
    // Parts of `a`: the file may go on after them.
    let m = parse(&seq(&[
        ROOT,
        &format!(
            r#"{{"name":"c","size":5,"sha256":"{}","contents":[{{"file":"a","offset":6}}]}}"#,
            world
        ),
        r#"{"name":"d","size":3,"contents":[{"file":"a","offset":2}]}"#,
        &format!(
            r#"{{"name":"e","size":5,"sha256":"{}","contents":[{{"file":"a","originalSize":11}}]}}"#,
            hello
        ),
        r#"{"name":"f","size":11,"contents":[{"file":"a","originalSize":11}]}"#,
        TRAILER,
    ]))
    .unwrap();
    dir_source(&dir).verify(&m).unwrap();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    v.assemble(&m, &mut dir_source(&dir), &AssembleOptions::default())
        .unwrap();
    for (name, data) in [("/c", "world"), ("/d", "llo"), ("/e", "hello"), ("/f", "hello world")] {
        let mut back = String::new();
        v.open_file(name).unwrap().read_to_string(&mut back).unwrap();
        assert_eq!(back, data, "{}", name);
    }
    // A part that runs past the end, and an originalSize that is not the
    // file's.
    for record in [
        r#"{"name":"g","size":6,"contents":[{"file":"a","offset":6}]}"#,
        r#"{"name":"h","size":5,"contents":[{"file":"a","originalSize":12}]}"#,
        r#"{"name":"i","size":5,"contents":[{"file":"a","originalSize":5}]}"#,
    ] {
        let m = parse(&seq(&[ROOT, record, TRAILER])).unwrap();
        let e = dir_source(&dir).verify(&m).unwrap_err();
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Source {
                    problem: SourceProblem::Size,
                    size: Some(11),
                    ..
                })
            ),
            "{}: {:?}",
            record,
            e
        );
    }
}

#[test]
fn source_files_stay_inside_the_source_directory() {
    let tmp = TempDir::new("manifest-beneath");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    std::fs::write(dir.join("outside.txt"), b"outside").unwrap();
    std::fs::write(dir.join("tree/sub/inside.txt"), b"inside").unwrap();
    std::os::unix::fs::symlink("sub/inside.txt", dir.join("tree/in.lnk")).unwrap();
    std::os::unix::fs::symlink("../outside.txt", dir.join("tree/out.lnk")).unwrap();
    std::os::unix::fs::symlink(dir.join("outside.txt"), dir.join("tree/abs.lnk")).unwrap();
    let record =
        |name: &str, file: &str| format!(r#"{{"name":"{}","size":6,"contents":[{{"file":"{}"}}]}}"#, name, file);
    let base = dir.join("tree");
    let (_img, mut v) = volume(8 << 20, 512, 512);
    // Plain files work; a symlink does not until asked for.
    let m = parse(&seq(&[ROOT, &record("a", "sub/inside.txt"), TRAILER])).unwrap();
    v.assemble(&m, &mut dir_source(&base), &AssembleOptions::default())
        .unwrap();
    let m = parse(&seq(&[ROOT, &record("b", "in.lnk"), TRAILER])).unwrap();
    assert!(v
        .assemble(&m, &mut dir_source(&base), &AssembleOptions::default())
        .is_err());
    v.assemble(
        &m,
        &mut dir_source(&base).follow_symlinks(true),
        &AssembleOptions::default(),
    )
    .unwrap();
    // Nothing leads out of the tree, however it is spelled.
    for file in ["out.lnk", "abs.lnk"] {
        let m = parse(&seq(&[ROOT, &record("c", file), TRAILER])).unwrap();
        assert!(
            v.assemble(
                &m,
                &mut dir_source(&base).follow_symlinks(true),
                &AssembleOptions::default()
            )
            .is_err(),
            "{}",
            file
        );
    }
    assert_eq!(v.read_dir("/").unwrap().len(), 2);
}

#[test]
fn directory_objects_after_their_children() {
    let m = parse(&seq(&[
        ROOT,
        r#"{"name":"d/x","size":0}"#,
        r#"{"name":"d","type":"dir","mTimeNSec":1700000000000000000}"#,
        TRAILER,
    ]))
    .unwrap();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut empty: &[u8] = &[];
    let opts = AssembleOptions {
        default_time: UNIX_EPOCH + Duration::from_secs(1_000_000_000),
        ..Default::default()
    };
    let r = v.assemble(&m, &mut StreamSource::new(&mut empty), &opts).unwrap();
    assert_eq!((r.files, r.directories), (1, 1));
    assert_eq!(
        v.metadata("/d").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
    assert_eq!(
        v.metadata("/d/x").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    );
}

#[test]
fn generator_leaves_the_manifest_out() {
    let tmp = TempDir::new("manifest-generate");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("Uapi16Manifest"), b"old").unwrap();
    std::fs::write(dir.join("Uapi16Manifest.sig"), b"old").unwrap();
    std::fs::write(dir.join("Uapi16Manifest2"), b"kept").unwrap();
    std::fs::write(dir.join("sub/Uapi16Manifest"), b"kept").unwrap();
    let m = parse(&generated(&dir)).unwrap();
    let names: Vec<&str> = m.entries.iter().filter_map(|e| e.name.as_deref()).collect();
    assert_eq!(names, vec!["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
}

#[test]
fn validity() {
    let m = parse(&seq(&[ROOT, r#"{"name":"x","size":0,"validity":"revoked"}"#, TRAILER])).unwrap();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut empty: &[u8] = &[];
    let opts = AssembleOptions {
        now_usec: Some(1),
        ..Default::default()
    };
    assert_eq!(
        v.assemble(&m, &mut StreamSource::new(&mut empty), &opts)
            .unwrap_err()
            .errno(),
        EKEYREVOKED
    );
    let m = parse(&seq(&[
        ROOT,
        r#"{"name":"d","type":"dir","validUntilUSec":10}"#,
        r#"{"name":"d/x","size":0}"#,
        TRAILER,
    ]))
    .unwrap();
    let opts = AssembleOptions {
        now_usec: Some(20),
        ..Default::default()
    };
    assert_eq!(
        v.assemble(&m, &mut StreamSource::new(&mut empty), &opts)
            .unwrap_err()
            .errno(),
        EKEYEXPIRED
    );
    let opts = AssembleOptions {
        now_usec: Some(5),
        ..Default::default()
    };
    assert!(v.assemble(&m, &mut StreamSource::new(&mut empty), &opts).is_ok());
}

/// mTimeNSec holds nanoseconds since the epoch in 64 bits: up to the year
/// 2554, and nothing before 1970.
#[test]
fn times_outside_mtime_nsec_have_none() {
    use std::time::{Duration, UNIX_EPOCH};
    let last = UNIX_EPOCH + Duration::from_nanos(u64::MAX);
    assert_eq!(generate::time_nsec(UNIX_EPOCH), Some(0));
    assert_eq!(generate::time_nsec(last), Some(u64::MAX));
    assert_eq!(generate::time_nsec(last + Duration::from_nanos(1)), None);
    assert_eq!(generate::time_nsec(UNIX_EPOCH - Duration::from_secs(1)), None);
}

/// Checks the progress a long operation reported: the counts only grow
/// and end at what its report says.
fn reported(seen: &[Progress], last: Progress) {
    assert!(
        seen.windows(2)
            .all(|w| w[0].files <= w[1].files && w[0].directories <= w[1].directories && w[0].bytes <= w[1].bytes),
        "{:?}",
        seen
    );
    assert_eq!(seen.last(), Some(&last));
}

/// The long operations tell their progress callback what they did so far,
/// after every entry and every chunk of a file: a copy, the manifest of
/// what was copied, an assembly from a manifest and a removal.
#[test]
fn long_operations_report_progress() {
    let tmp = TempDir::new("progress");
    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("big"), vec![0x5au8; 3 << 20]).unwrap();
    std::fs::write(tree.join("sub/small"), b"small").unwrap();
    let source = crate::host::open_dir(&tree).unwrap();
    let mut seen = Vec::new();

    let (_img, mut v) = volume(64 << 20, 512, 4096);
    let r = v
        .copy_tree_with_progress(source.as_fd(), "/tree", &CopyOptions::default(), &mut |p| seen.push(*p))
        .unwrap();
    // The big file reports its bytes in chunks, before it is done.
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: r.files,
            directories: r.directories,
            bytes: r.bytes,
        },
    );

    seen.clear();
    let w = volume::write_with_progress(&v, None, volume::Fields::default(), &mut Vec::new(), &mut |p| {
        seen.push(*p)
    })
    .unwrap();
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: w.files,
            directories: w.directories,
            bytes: w.bytes,
        },
    );

    seen.clear();
    let manifest = parse(&generated(&tree)).unwrap();
    let (_img2, mut v2) = volume(64 << 20, 512, 4096);
    let a = v2
        .assemble_with_progress(
            &manifest,
            &mut dir_source(&tree),
            &AssembleOptions::default(),
            &mut |p| seen.push(*p),
        )
        .unwrap();
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: a.files,
            directories: a.directories,
            bytes: a.bytes,
        },
    );

    seen.clear();
    let removed = v.remove_tree_with_progress("/tree", &mut |p| seen.push(*p)).unwrap();
    reported(
        &seen,
        Progress {
            files: removed.files,
            directories: removed.directories,
            bytes: 0,
        },
    );
    assert_eq!((removed.files, removed.directories), (2, 2));
}
