# SPDX-License-Identifier: LGPL-2.1-or-later

# Kani builds the crate root itself, see run.sh.
crate_roots += files('lib.rs')

run_target('verify',
           command : [files('run.sh'), files('lib.rs')])
