# SPDX-License-Identifier: LGPL-2.1-or-later

# Generates src/name/fold_table.rs from the Unicode tables of the compiler,
# see HACKING.md.
fold_table_gen = executable(
        'fold-table-gen',
        'fold-table.rs',
        build_by_default : false)
crate_roots += files('fold-table.rs')

fold_table = meson.project_source_root() / 'src/name/fold_table.rs'
fold_table_new = meson.current_build_dir() / 'fold_table.rs'

sh = find_program('sh')
run_target('update-fold-table',
           command : [sh, '-c', '"$1" >"$2" && cp "$2" "$3"',
                      'sh', fold_table_gen, fold_table_new, fold_table])
run_target('check-fold-table',
           command : [sh, '-c', '"$1" >"$2" && diff -u "$3" "$2"',
                      'sh', fold_table_gen, fold_table_new, fold_table])
