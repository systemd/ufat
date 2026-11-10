# SPDX-License-Identifier: LGPL-2.1-or-later

libvarlink = static_library(
        'varlink',
        'lib.rs',
        link_with : libjson)
crate_roots += files('lib.rs')

unit_tests_varlink = executable(
        'unit-tests-varlink',
        'lib.rs',
        link_with : libjson,
        rust_args : ['--test'] + test_rust_args)
test('unit-tests-varlink', unit_tests_varlink, protocol : 'rust')
