# SPDX-License-Identifier: LGPL-2.1-or-later

# Formats the small seed images of the corpus through the library, below
# the floor the command line tool enforces, see seeds.sh.
fuzz_seeds = executable(
        'fuzz-seeds',
        'seeds.rs',
        link_with : libufat,
        build_by_default : false)
crate_roots += files('seeds.rs')

run_target('fuzz',
           command : [files('run.sh'), ufat, fuzz_seeds, meson.project_build_root() / 'fuzz'])
