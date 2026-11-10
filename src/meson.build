# SPDX-License-Identifier: LGPL-2.1-or-later

libufat = static_library(
        'ufat',
        'lib.rs',
        link_with : libjson)
crate_roots += files('lib.rs')

unit_tests = executable(
        'unit-tests',
        'lib.rs',
        link_with : libjson,
        rust_args : ['--test'] + test_rust_args)
test('unit-tests', unit_tests, protocol : 'rust')
test_executables += unit_tests

# The library with the write trace of device.rs compiled in, for the crash
# consistency harness only. Nothing else links against it.
libufat_trace = static_library(
        'ufat_trace',
        'lib.rs',
        link_with : libjson,
        rust_args : ['--cfg=ufat_trace'])
