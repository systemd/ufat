# Hacking on ufat

ufat is built with meson and plain rustc. There is no cargo build and
there are no external crates.

## Requirements

- rustc 1.85 or newer. ufat has to keep building with rustc 1.85.
- meson 1.4 or newer and ninja.
- rustfmt, for the formatting check.

## Building

    meson setup build
    meson compile -C build

`meson compile` builds the library `build/src/libufat.rlib` and the
tests.

`RUSTC=` selects the compiler when the build directory is set up:

    RUSTC="rustup run 1.85.0 rustc" meson setup build-1.85

## Tests

    meson test -C build

`meson test` runs the unit tests of the library.

## Formatting

    meson compile -C build rustfmt
    meson test -C build --suite style

The code is formatted with rustfmt. rustfmt.toml sets the line width to
120 columns. The `rustfmt` target formats the code. The `style` test
suite checks the formatting. A plain `meson test` leaves it out.
