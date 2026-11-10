# SPDX-License-Identifier: LGPL-2.1-or-later

# The two helpers of run.sh.
genfile = executable(
        'genfile',
        'genfile.rs',
        build_by_default : false)
measure = executable(
        'measure',
        'measure.rs',
        link_with : [libvarlink, libjson],
        build_by_default : false)
crate_roots += files('genfile.rs', 'measure.rs')

run_target('bench',
           command : [files('run.sh')],
           depends : [ufat, genfile, measure],
           env : {'BUILD' : meson.project_build_root()})
