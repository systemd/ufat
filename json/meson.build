# SPDX-License-Identifier: LGPL-2.1-or-later

libjson = static_library(
        'json',
        'lib.rs')
crate_roots += files('lib.rs')

unit_tests_json = executable(
        'unit-tests-json',
        'lib.rs',
        rust_args : ['--test'] + test_rust_args)
test('unit-tests-json', unit_tests_json, protocol : 'rust')
