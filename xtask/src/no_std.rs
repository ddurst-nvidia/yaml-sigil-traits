// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Compile and dependency checks for the alloc-only public API.

use std::io;
use std::path::Path;
use std::process::{Command, Output};

const TOOLCHAIN: &str = "+1.95.0";
const TARGET: &str = "thumbv7em-none-eabi";
const DENIED_PACKAGES: &[&str] = &["getrandom", "jsonschema", "tokio", "tracing"];
const DENIED_FEATURES: &[&str] = &["getrandom", "pem", "pkcs8", "std"];

pub(crate) fn run(root: &Path) -> io::Result<()> {
    run_cargo(
        root,
        &[
            TOOLCHAIN,
            "fmt",
            "--manifest-path",
            "no-std-probe/Cargo.toml",
            "--all",
            "--check",
        ],
        "alloc-only consumer formatting",
    )?;
    run_cargo(
        root,
        &[
            TOOLCHAIN,
            "check",
            "--lib",
            "--no-default-features",
            "--target",
            TARGET,
        ],
        "alloc-only traits target check",
    )?;
    run_cargo(
        root,
        &[
            TOOLCHAIN,
            "check",
            "--manifest-path",
            "no-std-probe/Cargo.toml",
            "--target",
            TARGET,
        ],
        "alloc-only consumer target check",
    )?;
    run_cargo(
        root,
        &[TOOLCHAIN, "test", "--no-default-features"],
        "alloc-only host tests",
    )?;

    let output = cargo_output(
        root,
        &[
            TOOLCHAIN,
            "tree",
            "--edges",
            "normal",
            "--no-default-features",
            "--target",
            TARGET,
            "--format",
            "{p}|{f}",
        ],
        "alloc-only dependency audit",
    )?;
    validate_dependency_tree(&String::from_utf8_lossy(&output.stdout))
}

fn run_cargo(root: &Path, args: &[&str], label: &str) -> io::Result<()> {
    eprintln!("+ cargo {} (cwd {})", args.join(" "), root.display());
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{label} failed with {status}")))
    }
}

fn cargo_output(root: &Path, args: &[&str], label: &str) -> io::Result<Output> {
    eprintln!("+ cargo {} (cwd {})", args.join(" "), root.display());
    let output = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "{label} failed with {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn validate_dependency_tree(tree: &str) -> io::Result<()> {
    for line in tree.lines() {
        let Some((package, features)) = line.split_once('|') else {
            return Err(io::Error::other(format!(
                "unexpected cargo tree line: {line}"
            )));
        };
        let package = package
            .trim_start_matches(|character: char| !character.is_ascii_alphanumeric())
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if DENIED_PACKAGES.contains(&package) {
            return Err(io::Error::other(format!(
                "alloc-only graph contains denied package {package}"
            )));
        }
        for feature in features.split(',').filter(|feature| !feature.is_empty()) {
            if DENIED_FEATURES.contains(&feature) {
                return Err(io::Error::other(format!(
                    "alloc-only graph enables denied feature {feature} on {package}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_dependency_tree;

    #[test]
    fn dependency_audit_accepts_alloc_only_features() {
        validate_dependency_tree(
            "yaml-sigil-traits v0.0.0|\n├── ed25519-dalek v2.2.0|alloc,fast,zeroize\n",
        )
        .unwrap();
    }

    #[test]
    fn dependency_audit_rejects_std_and_entropy_backends() {
        assert!(validate_dependency_tree("crate v1.0.0|alloc,std\n").is_err());
        assert!(validate_dependency_tree("└── getrandom v0.3.0|\n").is_err());
    }
}
