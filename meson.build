# SPDX-License-Identifier: LGPL-2.1-or-later

project('ufat', 'rust',
        license : 'LGPL-2.1-or-later',
        default_options : [
                'buildtype=debugoptimized',
                'rust_std=2021',
        ],
        meson_version : '>= 1.4.0',
)

# ufat has to keep building with this rustc.
rust_msrv = '1.85'
rustc = meson.get_compiler('rust')
if rustc.version().version_compare('< ' + rust_msrv)
        error('rustc >= @0@ is required, found @1@'.format(rust_msrv, rustc.version()))
endif

add_project_arguments(
        '-Wunreachable_pub',
        '-Wunused_qualifications',
        # rustc warns about any cfg not listed here.
        '--check-cfg=cfg(test)',
        '--check-cfg=cfg(kani)',
        language : 'rust')

# The tests always run with overflow checks and debug assertions.
test_rust_args = ['-Coverflow-checks=yes', '-Cdebug-assertions=yes']

# The style checks run with --suite style only.
add_test_setup('default',
               exclude_suites : ['style'],
               is_default : true)

# Every crate root, for rustfmt. It follows the mod declarations from there.
crate_roots = []

subdir('json')
subdir('src')
subdir('tools')
subdir('tests')
subdir('verify')

rustfmt = find_program('rustfmt', required : false)
if rustfmt.found()
        test('rustfmt',
             rustfmt,
             args : ['--check', '--edition', '2021', crate_roots],
             suite : 'style')
        run_target('rustfmt',
                   command : [rustfmt, '--edition', '2021', crate_roots])
endif
