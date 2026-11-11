// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the tests of this crate share.

use crate::name::Name;

/// The name `bytes` are, for a test that knows them to be one.
pub(crate) fn named(bytes: &[u8]) -> Name<'_> {
    Name::new(bytes).unwrap()
}
