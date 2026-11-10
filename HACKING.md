# Hacking on ufat

ufat is built with cargo. The libc crate is its only external
dependency.

## Requirements

- rustc and cargo 1.85 or newer. ufat has to keep building with rustc
  1.85.
- rustfmt, for the formatting check, and clippy, for the lints.

## Building

    cargo build --locked

`cargo build` builds the library.

Cargo.lock is part of the tree. `--locked` makes cargo use the versions
it lists.

With rustup, `cargo +1.85.0` selects rustc 1.85:

    cargo +1.85.0 build --locked

## Tests

    cargo test --locked

`cargo test` runs the unit tests of the library.

The tests build with the dev profile, which is optimized and keeps the
overflow checks and debug assertions. `--release` turns those off.

## Formatting

    cargo fmt --all
    cargo fmt --all --check

The code is formatted with rustfmt. rustfmt.toml sets the line width to
120 columns. `cargo fmt --all` formats the code, and `--check` checks
it.

## Lints

    cargo clippy --locked --workspace --all-targets -- -D warnings

clippy checks the library and its tests. It takes the oldest rustc ufat
builds with from `rust-version` in Cargo.toml, so it does not suggest
functions that rustc 1.85 lacks.

The lints depend on the target and on the version of rustc. `--target`
checks another architecture once `rustup target add` has installed it.
That needs no cross linker.
