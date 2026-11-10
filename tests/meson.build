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

foreach name : ['fixtures', 'cli']
        exe = executable(
                'test-' + name,
                name + '.rs',
                link_with : libufat,
                rust_args : ['--test'] + test_rust_args)
        test('test-' + name,
             exe,
             env : integration_env,
             depends : ufat,
             protocol : 'rust',
             timeout : 300)
        crate_roots += files(name + '.rs')
endforeach
