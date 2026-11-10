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
