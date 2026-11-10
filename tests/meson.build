# SPDX-License-Identifier: LGPL-2.1-or-later

# The exhaustive sweeps take minutes, they run with -Dslow-tests=true only.
crate_roots += files('exhaustive.rs')
if get_option('slow-tests')
        test_exhaustive = executable(
                'test-exhaustive',
                'exhaustive.rs',
                link_with : libufat,
                rust_args : ['--test'] + test_rust_args)
        test('test-exhaustive',
             test_exhaustive,
             protocol : 'rust',
             suite : 'slow',
             timeout : 0)
endif

integration_env = {
        'UFAT' : ufat.full_path(),
        'UFAT_FIXTURES' : meson.current_source_dir() / 'fixtures',
}

foreach name : ['fixtures', 'cli', 'reference', 'varlink']
        exe = executable(
                'test-' + name,
                name + '.rs',
                link_with : [libufat, libvarlink, libjson],
                rust_args : ['--test'] + test_rust_args)
        test('test-' + name,
             exe,
             env : integration_env,
             depends : ufat,
             protocol : 'rust',
             timeout : 300)
        crate_roots += files(name + '.rs')
        test_executables += exe
endforeach

# crash.rs links the library with the write trace under the name ufat.
test_crash = executable(
        'test-crash',
        'crash.rs',
        link_with : libufat_trace,
        rust_dependency_map : {'ufat_trace' : 'ufat'},
        rust_args : ['--test'] + test_rust_args)
test('test-crash',
     test_crash,
     args : ['--test-threads=1'],
     protocol : 'rust',
     timeout : 300)
crate_roots += files('crash.rs')
test_executables += test_crash

subdir('fuzz')
