// SPDX-License-Identifier: LGPL-2.1-or-later
//! Exhaustive and property sweeps over the pure parts of the library. They
//! take a few minutes and are ignored by default; run them with
//! `cargo test --locked --test exhaustive -- --ignored`.

use std::thread;

use fat::dirent::NAME_BASE;
use fat::layout::*;
use fat::name::{fold_str, join_long_name, long_name_entries, parse_long_name_entry, Alias, LongName};
use fat::time::{FatTimestamp, FAT_EPOCH, FAT_MAX, FAT_MAX_NANOS};

fn threads() -> u64 {
    thread::available_parallelism().map_or(4, |n| n.get() as u64)
}

fn check_layout(p: &LayoutParams, total: u64, l: &Layout) -> Result<(), String> {
    if u64::from(l.total_sectors) > total {
        return Err(format!("total_sectors {} > device {}", l.total_sectors, total));
    }
    if l.used_sectors() > u64::from(l.total_sectors) {
        return Err(format!("used {} > total {}", l.used_sectors(), l.total_sectors));
    }
    if l.fat_entries() > l.fat_capacity() {
        return Err(format!(
            "fat_entries {} > capacity {}",
            l.fat_entries(),
            l.fat_capacity()
        ));
    }
    if l.clusters == 0 || l.clusters > MAX_CLUSTERS {
        return Err(format!("clusters {} out of range", l.clusters));
    }
    if !p.allow_small && l.clusters < MIN_CLUSTERS {
        return Err(format!("clusters {} below the minimum", l.clusters));
    }
    if l.reserved_sectors < p.reserved_sectors {
        return Err("reserved sectors shrank".into());
    }
    if p.align
        && l.total_sectors > ALIGNMENT_THRESHOLD_SECTORS
        && (l.reserved_sectors % l.sectors_per_cluster != 0 || l.fat_sectors % l.sectors_per_cluster != 0)
    {
        return Err("misaligned".into());
    }
    if !(l.used_sectors() + u64::from(l.sectors_per_cluster) > u64::from(l.total_sectors)
        || l.fat_entries() + 1 > l.fat_capacity())
    {
        return Err("one more cluster would have fit".into());
    }
    Ok(())
}

fn params(ss: u32, spc: Option<u32>, fats: u32, align: bool, allow_small: bool, track: Option<u32>) -> LayoutParams {
    LayoutParams {
        sector_size: ss,
        sectors_per_cluster: spc,
        reserved_sectors: DEFAULT_RESERVED_SECTORS,
        fats,
        align,
        track_sectors: track,
        allow_small,
    }
}

/// Runs compute() over every `stride`th total in the u32 range.
fn sweep_compute(p: LayoutParams, stride: u64) {
    let n = threads();
    let span = (1u64 << 32) / n;
    let problems: Vec<String> = thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|t| {
                s.spawn(move || {
                    let mut found = Vec::new();
                    let mut total = t * span;
                    while total < (t + 1) * span {
                        if let Ok(l) = compute(&p, total) {
                            if let Err(e) = check_layout(&p, total, &l) {
                                found.push(format!("{:?} total {}: {} ({:?})", p, total, e, l));
                                if found.len() > 3 {
                                    break;
                                }
                            }
                        }
                        total += stride;
                    }
                    found
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    assert!(problems.is_empty(), "{:#?}", problems);
    for big in [1u64 << 32, (1u64 << 32) + 1, u64::MAX / 4096, u64::MAX] {
        if let Ok(l) = compute(&p, big) {
            check_layout(&p, big, &l).unwrap();
        }
    }
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn compute_over_every_total() {
    // Every total, for the parameters systemd-repart would use.
    sweep_compute(params(512, None, 2, true, true, None), 1);
    sweep_compute(params(4096, None, 2, true, false, None), 1);
    // Strided for the rest of the parameter space.
    for ss in [512u32, 1024, 2048, 4096] {
        for spc in [None, Some(1u32), Some(2), Some(8), Some(32), Some(128)] {
            for fats in [1u32, 2, 4] {
                for align in [true, false] {
                    for track in [None, Some(63u32)] {
                        sweep_compute(params(ss, spc, fats, align, true, track), 1009);
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn minimal_is_the_exact_inverse_of_compute() {
    let needs = || (1u32..=200_000).chain((200_001..=MAX_CLUSTERS).step_by(104_729));
    let mut sets = Vec::new();
    for ss in [512u32, 4096] {
        for spc in [1u32, 2, 8, 64, 128] {
            for fats in [1u32, 2] {
                for align in [true, false] {
                    for track in [None, Some(63u32)] {
                        sets.push(params(ss, Some(spc), fats, align, true, track));
                    }
                }
            }
        }
    }
    for ss in [512u32, 4096] {
        for spc in [1u32, 8] {
            sets.push(params(ss, Some(spc), 2, true, false, None));
        }
    }
    thread::scope(|s| {
        for chunk in sets.chunks(sets.len().div_ceil(threads() as usize)) {
            s.spawn(move || {
                for p in chunk {
                    let spc = u64::from(p.sectors_per_cluster.unwrap());
                    let max_need = (u64::from(u32::MAX) / spc).min(u64::from(MAX_CLUSTERS)) as u32;
                    for need in needs().filter(|&n| n <= max_need) {
                        let l = minimal(p, need).unwrap_or_else(|e| panic!("{:?} need {}: {}", p, need, e));
                        let want = need.max(if p.allow_small { 1 } else { MIN_CLUSTERS });
                        assert!(l.clusters >= want, "{:?} need {}: {:?}", p, need, l);
                        assert_eq!(compute(p, u64::from(l.total_sectors)).unwrap(), l);
                        // Nothing smaller works: not one cluster less, and not
                        // any sector count in between either.
                        let total = u64::from(l.total_sectors);
                        for smaller in (total.saturating_sub(spc)..total).rev() {
                            if let Ok(s) = compute(p, smaller) {
                                assert!(
                                    s.clusters < want,
                                    "{:?} need {}: {} sectors still give {} clusters",
                                    p,
                                    need,
                                    smaller,
                                    s.clusters
                                );
                            }
                        }
                    }
                }
            });
        }
    });
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn every_second_round_trips() {
    let n = threads() as i64;
    let span = (FAT_MAX - FAT_EPOCH + 1) / n + 1;
    thread::scope(|s| {
        for t in 0..n {
            s.spawn(move || {
                let start = FAT_EPOCH + t * span;
                let end = (start + span).min(FAT_MAX + 1);
                for secs in start..end {
                    for nanos in [0u32, 999_999_999] {
                        let ts = FatTimestamp::from_unix(secs, nanos);
                        let (back, back_nanos) = ts.to_unix();
                        assert_eq!(back, secs);
                        let expected = if secs == FAT_MAX {
                            nanos.min(FAT_MAX_NANOS)
                        } else {
                            nanos
                        };
                        assert_eq!(back_nanos, expected / 10_000_000 * 10_000_000, "secs {}", secs);
                    }
                }
            });
        }
    });
    assert_eq!(FatTimestamp::from_unix(FAT_EPOCH - 1, 0), FatTimestamp::EPOCH);
    assert_eq!(FatTimestamp::from_unix(i64::MIN, 0), FatTimestamp::EPOCH);
    assert_eq!(FatTimestamp::from_unix(i64::MAX, 0).to_unix(), (FAT_MAX, FAT_MAX_NANOS));
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn every_timestamp_word_round_trips() {
    let n = threads();
    let span = (1u64 << 32) / n;
    thread::scope(|s| {
        for t in 0..n {
            s.spawn(move || {
                for word in t * span..(t + 1) * span {
                    let ts = FatTimestamp {
                        date: (word >> 16) as u16,
                        time: word as u16,
                        tenths: 0,
                    };
                    let month = (ts.date >> 5) & 0x0f;
                    let day = ts.date & 0x1f;
                    let valid = (1..=12).contains(&month)
                        && day >= 1
                        && day <= days_in_month(1980 + i64::from(ts.date >> 9), u32::from(month))
                        && (ts.time >> 11) < 24
                        && ((ts.time >> 5) & 0x3f) < 60
                        && (ts.time & 0x1f) < 30;
                    let (secs, nanos) = ts.to_unix();
                    let back = FatTimestamp::from_unix(secs, nanos);
                    if valid {
                        assert_eq!(back, ts, "word {:#x}", word);
                        let with_tenths = FatTimestamp { tenths: 199, ..ts };
                        let (secs, nanos) = with_tenths.to_unix();
                        assert_eq!(FatTimestamp::from_unix(secs, nanos), with_tenths);
                    } else {
                        // Garbage fields decode to something inside the range.
                        assert!((FAT_EPOCH..=FAT_MAX).contains(&back.to_unix().0));
                    }
                }
            });
        }
    });
}

fn days_in_month(year: i64, month: u32) -> u16 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn case_folding_is_idempotent_over_all_code_points() {
    for c in char::MIN..=char::MAX {
        let s = c.to_string();
        let once = fold_str(&s);
        let twice = fold_str(&String::from_utf16_lossy(&once));
        assert_eq!(once, twice, "{:?}", c);
    }
}

#[test]
#[ignore = "takes minutes, run with --ignored"]
fn every_single_character_name_round_trips() {
    for c in char::MIN..=char::MAX {
        let s = c.to_string();
        match LongName::new(&s) {
            Ok(n) => {
                let entries = long_name_entries(&n, 0x42);
                let parsed: Vec<_> = entries
                    .iter()
                    .rev()
                    .map(|e| parse_long_name_entry(e).unwrap())
                    .collect();
                assert_eq!(join_long_name(&parsed), n.units(), "{:?}", c);
            }
            Err(_) => assert!(
                (c as u32) < 0x20
                    || c == '\x7f'
                    || c == '.'
                    || c == ' '
                    || c == '\u{ffff}'
                    || "\"*/:<>?\\|".contains(c),
                "{:?} rejected",
                c
            ),
        }
    }
}

/// Every alias of a name of up to three printable ASCII characters is a
/// legal, space padded 8.3 name, and the name's long name entries round
/// trip. 866495 names.
#[test]
#[ignore = "takes minutes, run with --ignored"]
fn every_short_ascii_name_has_a_legal_alias() {
    fn legal(b: u8) -> bool {
        b == b' ' || b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'()-@^_`{}~".contains(&b)
    }
    let printable: Vec<char> = (0x20u8..0x7f).map(char::from).collect();
    let mut names = Vec::with_capacity(866_495);
    for &a in &printable {
        names.push(a.to_string());
        for &b in &printable {
            names.push(format!("{}{}", a, b));
            for &c in &printable {
                names.push(format!("{}{}{}", a, b, c));
            }
        }
    }
    let mut accepted = 0;
    for s in &names {
        let Ok(name) = LongName::new(s) else { continue };
        accepted += 1;
        let alias = Alias::of(&name);
        assert!(alias.name.iter().all(|&b| legal(b)), "{:?} -> {:?}", s, alias.name);
        assert!(
            alias.base_len <= NAME_BASE.len() && alias.name[alias.base_len..NAME_BASE.end].iter().all(|&b| b == b' '),
            "{:?}",
            s
        );
        assert!(!alias.needs_long_name || alias.case_flags == 0, "{:?}", s);
        let tailed = alias.with_tail(1);
        assert!(
            tailed.iter().all(|&b| legal(b)) && tailed[NAME_BASE].contains(&b'~'),
            "{:?}",
            s
        );
        let entries = long_name_entries(&name, 0x42);
        let parsed: Vec<_> = entries
            .iter()
            .rev()
            .map(|e| parse_long_name_entry(e).unwrap())
            .collect();
        assert_eq!(join_long_name(&parsed), name.units(), "{:?}", s);
    }
    // 86 of the 95 characters are allowed in names; a name cannot start
    // with a space or end with a space or a dot, which rules out "." and
    // ".." as well: 84 + 85 * 84 + 85 * 86 * 84 names are accepted.
    assert_eq!(accepted, 621_264);
}
