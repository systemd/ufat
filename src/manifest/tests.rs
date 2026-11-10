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
