//! CLI entry points for the layer-1 reference suite and artifact reproduction.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Subcommand;
use ozpb_api_types::{DryRunInput, ReferenceSuiteInput, VerifyInput};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{print_json, read_json, BuildConfigArgs};

#[derive(Subcommand)]
pub enum Command {
    /// Bind a candidate to reference/reproduction evidence; runtime layers stay unavailable.
    PrepareDryRun {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        registry_roots: PathBuf,
        #[arg(long)]
        registry_min_version: u64,
        #[arg(long)]
        rpc_sources: PathBuf,
        #[command(flatten)]
        build: BuildConfigArgs,
    },
    /// Run the offline reference suite (layer 1 only; not a full dry run).
    ReferenceSuite {
        #[arg(long)]
        spec: PathBuf,
        /// Print the suite's cases (invocation and context per case, i128 as decimal strings)
        /// under the hash that names them, instead of the evaluated report.
        #[arg(long)]
        emit_cases: bool,
    },
    /// Reproduce a generated crate and Wasm, reporting each verification dimension.
    Verify {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value_t = 0)]
        rule: usize,
        /// Root of the generated crate, including Cargo.toml and src/.
        #[arg(long)]
        generated_dir: PathBuf,
        /// Generated Wasm artifact to reproduce.
        #[arg(long)]
        wasm: PathBuf,
        /// BuildManifest emitted alongside the generated crate.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        build: BuildConfigArgs,
    },
}

impl Command {
    pub fn run(self) -> Result<()> {
        match self {
            Self::PrepareDryRun {
                request,
                registry_roots,
                registry_min_version,
                rpc_sources,
                build,
            } => {
                let input: DryRunInput = serde_json::from_value(read_json(&request)?)?;
                let roots = std::fs::read_to_string(&registry_roots)
                    .with_context(|| format!("reading {}", registry_roots.display()))?;
                let trust =
                    ozpb_toolkit::registry_trust_from_roots_json(&roots, registry_min_version)?;
                let sources = std::fs::read_to_string(&rpc_sources)
                    .with_context(|| format!("reading {}", rpc_sources.display()))?;
                let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;
                ozpb_toolkit::resolve_rpc_source(
                    &sources,
                    &input.candidate.rpc_source,
                    &input.candidate.network_id,
                )?;
                let output = ozpb_toolkit::prepare_dry_run_with_build_config(
                    &input,
                    &trust,
                    &build.resolve()?,
                )?;
                print_json(&output)?;
            }
            Self::ReferenceSuite { spec, emit_cases } => {
                let input = ReferenceSuiteInput {
                    spec: read_json(&spec)?,
                };
                if emit_cases {
                    print_json(&ozpb_toolkit::reference_suite_cases(&input)?)?;
                } else {
                    print_json(&ozpb_toolkit::reference_suite(&input)?)?;
                }
            }
            Self::Verify {
                spec,
                rule,
                generated_dir,
                wasm,
                manifest,
                build,
            } => {
                let claimed = read_generated_files(&generated_dir, &wasm, &manifest)?;
                let claimed_wasm =
                    std::fs::read(&wasm).with_context(|| format!("reading {}", wasm.display()))?;
                let mut result = ozpb_toolkit::verify_with_build_config(
                    &VerifyInput {
                        spec: read_json(&spec)?,
                        rule_index: rule,
                        claimed_generated_files: claimed.files,
                        claimed_wasm_base64: Some(
                            base64::engine::general_purpose::STANDARD.encode(claimed_wasm),
                        ),
                        claimed_build_manifest: Some(read_json(&manifest)?),
                        generated_artifact: None,
                    },
                    &build.resolve()?,
                )?;
                if !claimed.unrepresentable.is_empty() {
                    result.matches = false;
                    result.source_reproduction = format!(
                        "MISMATCH: generated files have paths or contents that are not UTF-8: {}",
                        claimed.unrepresentable.join(", ")
                    );
                }
                print_json(&result)?;
            }
        }
        Ok(())
    }
}

/// Read the complete generated crate, except Cargo.lock and the separately supplied
/// Wasm/manifest artifacts. The toolkit compares this exact path set with regeneration.
#[derive(Debug)]
struct ClaimedFiles {
    files: BTreeMap<String, String>,
    unrepresentable: Vec<String>,
}

fn read_generated_files(
    generated_dir: &Path,
    wasm: &Path,
    manifest: &Path,
) -> Result<ClaimedFiles> {
    // A trailing separator makes symlink_metadata follow the link on Unix.
    let root_entry: PathBuf = generated_dir.components().collect();
    if std::fs::symlink_metadata(&root_entry)
        .with_context(|| format!("reading {}", generated_dir.display()))?
        .file_type()
        .is_symlink()
    {
        bail!(
            "generated crate root cannot be a symlink: {}",
            generated_dir.display()
        );
    }
    let root = generated_dir
        .canonicalize()
        .with_context(|| format!("reading {}", generated_dir.display()))?;
    if !root.is_dir() {
        bail!(
            "generated crate root is not a directory: {}",
            root.display()
        );
    }
    let wasm = wasm
        .canonicalize()
        .with_context(|| format!("reading {}", wasm.display()))?;
    let manifest = manifest
        .canonicalize()
        .with_context(|| format!("reading {}", manifest.display()))?;

    let mut files = BTreeMap::new();
    let mut unrepresentable = Vec::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("reading {}", directory.display()))?
        {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            let path = entry.path();
            let relative = path.strip_prefix(&root)?;
            let kind = entry
                .file_type()
                .with_context(|| format!("reading {}", path.display()))?;
            if kind.is_symlink() {
                bail!("generated crate contains a symlink: {}", path.display());
            }
            if relative == Path::new("Cargo.lock") || path == wasm || path == manifest {
                continue;
            }
            if kind.is_dir() {
                directories.push(path);
                continue;
            }
            if !kind.is_file() {
                bail!(
                    "generated crate contains a non-file entry: {}",
                    path.display()
                );
            }
            let contents = std::fs::read(&path)
                .with_context(|| format!("reading generated file {}", path.display()))?;
            match (relative.to_str(), String::from_utf8(contents)) {
                (Some(key), Ok(contents)) => {
                    files.insert(key.replace(std::path::MAIN_SEPARATOR, "/"), contents);
                }
                _ => unrepresentable.push(format!("{relative:?}")),
            }
        }
    }
    unrepresentable.sort();
    Ok(ClaimedFiles {
        files,
        unrepresentable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command as CliCommand};
    use clap::Parser;

    #[test]
    fn preparation_requires_operator_registry_and_rpc_configuration() {
        assert!(Cli::try_parse_from([
            "ozpb",
            "prepare-dry-run",
            "--request",
            "request.json",
            "--registry-roots",
            "roots.json",
            "--registry-min-version",
            "3",
            "--rpc-sources",
            "sources.json",
        ])
        .is_ok());
        assert!(
            Cli::try_parse_from(["ozpb", "prepare-dry-run", "--request", "request.json",]).is_err()
        );
    }

    #[test]
    fn commands_parse_at_the_top_level_with_the_crate_root_and_build_flags() {
        let suite = Cli::try_parse_from(["ozpb", "reference-suite", "--spec", "spec.json"])
            .expect("reference suite command");
        assert!(matches!(
            suite.command,
            CliCommand::Verification(Command::ReferenceSuite {
                emit_cases: false,
                ..
            })
        ));
        let cases = Cli::try_parse_from([
            "ozpb",
            "reference-suite",
            "--spec",
            "spec.json",
            "--emit-cases",
        ])
        .expect("reference suite cases");
        assert!(matches!(
            cases.command,
            CliCommand::Verification(Command::ReferenceSuite {
                emit_cases: true,
                ..
            })
        ));

        let verify = Cli::try_parse_from([
            "ozpb",
            "verify",
            "--spec",
            "spec.json",
            "--generated-dir",
            "generated",
            "--wasm",
            "generated/policy.wasm",
            "--manifest",
            "generated/build-manifest.json",
            "--build-jobs",
            "2",
        ])
        .expect("verify command");
        match verify.command {
            CliCommand::Verification(Command::Verify {
                generated_dir,
                build,
                ..
            }) => {
                assert_eq!(generated_dir, Path::new("generated"));
                assert_eq!(build.build_jobs, Some(2));
            }
            _ => panic!("expected verify command"),
        }
    }

    #[test]
    fn generated_file_reader_includes_every_non_lock_file_and_rejects_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("generated");
        std::fs::create_dir_all(root.join("src")).unwrap();
        for (path, contents) in [
            ("Cargo.toml", "package"),
            ("rust-toolchain.toml", "toolchain"),
            ("src/lib.rs", "lib"),
            ("src/contract.rs", "contract"),
            ("src/extra.rs", "extra"),
            ("Cargo.lock", "lock"),
            ("policy.wasm", "wasm"),
            ("build-manifest.json", "{}"),
        ] {
            std::fs::write(root.join(path), contents).unwrap();
        }
        let claimed = read_generated_files(
            &root,
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .unwrap();
        assert!(claimed.unrepresentable.is_empty());
        let files = claimed.files;
        assert_eq!(files.len(), 5);
        assert_eq!(files.get("Cargo.toml"), Some(&"package".to_string()));
        assert_eq!(files.get("src/extra.rs"), Some(&"extra".to_string()));
        assert!(!files.contains_key("Cargo.lock"));
        assert!(!files.contains_key("build-manifest.json"));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path(), root.join("src/outside")).unwrap();
            let error = read_generated_files(
                &root,
                &root.join("policy.wasm"),
                &root.join("build-manifest.json"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("symlink"));
        }
    }

    #[test]
    fn binary_extra_file_is_recorded_as_a_source_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join("policy.wasm"), b"wasm").unwrap();
        std::fs::write(root.join("build-manifest.json"), b"{}").unwrap();
        std::fs::write(root.join("extra.bin"), [0xff]).unwrap();

        let claimed = read_generated_files(
            root,
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .unwrap();
        assert_eq!(claimed.unrepresentable, vec!["\"extra.bin\"".to_string()]);
    }

    // APFS rejects invalid UTF-8 names, so exercise this case on Linux filesystems.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_extra_name_is_recorded_as_a_source_mismatch() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join("policy.wasm"), b"wasm").unwrap();
        std::fs::write(root.join("build-manifest.json"), b"{}").unwrap();
        let name = std::ffi::OsString::from_vec(b"extra-\xff".to_vec());
        std::fs::write(root.join(name), b"contents").unwrap();

        let claimed = read_generated_files(
            root,
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .unwrap();
        assert_eq!(claimed.unrepresentable.len(), 1);
        assert!(claimed.unrepresentable[0].contains("extra-"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_root_symlinks_with_a_trailing_separator_and_lockfile_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("generated");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("policy.wasm"), b"wasm").unwrap();
        std::fs::write(root.join("build-manifest.json"), b"{}").unwrap();
        let link = temp.path().join("linked");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let mut link_with_separator = link.as_os_str().to_os_string();
        link_with_separator.push("/");
        let error = read_generated_files(
            &PathBuf::from(link_with_separator),
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("root cannot be a symlink"));

        std::os::unix::fs::symlink(root.join("policy.wasm"), root.join("Cargo.lock")).unwrap();
        let error = read_generated_files(
            &root,
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("contains a symlink"));
    }
}
