// SPDX-License-Identifier: LGPL-2.1-or-later
//! Paths inside a volume.
//!
//! A path is a sequence of names separated by slashes. Leading, trailing
//! and repeated slashes carry no meaning. "." and ".." are rejected: there
//! is no working directory to resolve them against, and a FAT directory
//! stores them as entries of their own.

use crate::errno::*;
use crate::Result;
use crate::{Detail, NameProblem};

/// Longest path accepted, in bytes: Linux's PATH_MAX without the NUL. A
/// longer path could not be opened on the mounted volume in one go, and
/// without a bound the paths a tree walk builds grow with the tree.
pub(crate) const MAX_PATH: usize = 4095;

/// Splits `path` into its names.
pub(crate) fn components(path: &str) -> Result<Vec<&str>> {
    let bad = |problem: NameProblem| Detail::Name {
        name: path.to_string(),
        problem,
    };
    if path.len() > MAX_PATH {
        bail!(
            ENAMETOOLONG,
            bad(NameProblem::TooLong),
            "path is longer than {} bytes",
            MAX_PATH
        );
    }
    let mut out = Vec::new();
    for c in path.split('/') {
        if c.is_empty() {
            continue;
        }
        if c == "." || c == ".." {
            bail!(
                EINVAL,
                bad(NameProblem::DotComponent),
                "path '{}' contains a '{}' component",
                path,
                c
            );
        }
        out.push(c);
    }
    Ok(out)
}

/// Appends `name` to the directory path `dir`.
pub(crate) fn join(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_and_joining() {
        assert_eq!(components("/").unwrap(), Vec::<&str>::new());
        assert_eq!(components("").unwrap(), Vec::<&str>::new());
        assert_eq!(components("/EFI//Linux/").unwrap(), vec!["EFI", "Linux"]);
        assert_eq!(components("EFI/Linux").unwrap(), vec!["EFI", "Linux"]);
        assert_eq!(components("/EFI/./x").unwrap_err().errno(), EINVAL);
        assert_eq!(components("../x").unwrap_err().errno(), EINVAL);
        assert_eq!(join("/", "EFI"), "/EFI");
        assert_eq!(join("", "EFI"), "/EFI");
        assert_eq!(join("/EFI/", "Linux"), "/EFI/Linux");
        assert_eq!(join("/EFI", "Linux"), "/EFI/Linux");
        let long = format!("/{}", "x".repeat(MAX_PATH - 1));
        assert_eq!(components(&long).unwrap().len(), 1);
        assert_eq!(components(&format!("{}x", long)).unwrap_err().errno(), ENAMETOOLONG);
    }
}
