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
        '--check-cfg=cfg(ufat_trace)',
        language : 'rust')

# The tests always run with overflow checks and debug assertions.
test_rust_args = ['-Coverflow-checks=yes', '-Cdebug-assertions=yes']

# With -Db_coverage=true the tests leave their profiles for the
# coverage-report target.
coverage_env = {}
if get_option('b_coverage')
        coverage_env += {'LLVM_PROFILE_FILE' : meson.project_build_root() / 'coverage' / '%p-%m.profraw'}
endif

# The style checks run with --suite style only.
add_test_setup('default',
               exclude_suites : ['style'],
               env : coverage_env,
               is_default : true)

# Every crate root, for rustfmt. It follows the mod declarations from there.
crate_roots = []
# Every test binary, for the coverage report.
test_executables = []

subdir('json')
subdir('src')
subdir('varlink')

# meson links with -Cdefault-linker-libraries, which makes a crt-static
# binary dynamically linked again.
ufat = executable(
        'ufat',
        'src/bin/ufat/main.rs',
        link_with : [libufat, libvarlink, libjson],
        rust_args : get_option('static') ? ['-Ctarget-feature=+crt-static', '-Cdefault-linker-libraries=no'] : [],
        install : true)
crate_roots += files('src/bin/ufat/main.rs')

subdir('tools')
subdir('tests')
subdir('verify')
subdir('bench')

rustfmt = find_program('rustfmt', required : false)
if rustfmt.found()
        test('rustfmt',
             rustfmt,
             args : ['--check', '--edition', '2021', crate_roots],
             suite : 'style')
        run_target('rustfmt',
                   command : [rustfmt, '--edition', '2021', crate_roots])
endif

if get_option('b_coverage')
        run_target('coverage-report',
                   command : [files('tools/coverage.sh'),
                              meson.project_build_root() / 'coverage',
                              test_executables,
                              ufat])
endif
