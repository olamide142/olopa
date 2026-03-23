use std::fs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use oilc::{compile_many, diagnostics::format_diagnostic, CompileUnitInput, CompilerConfig, Diagnostic};

// CLI arguments for the `oilc` compiler binary.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct OilCompilerArgs {
    // One or more files/directories containing `.oil` inputs.
    #[arg(
        short,
        long,
        required = true,
        action = clap::ArgAction::Append,
        num_args = 1
    )]
    source: Vec<String>,

    // Optional debug dump of lexed tokens.
    #[arg(long, default_value_t = false)]
    dump_tokens: bool,

    // Optional debug dump of parsed AST.
    #[arg(long, default_value_t = false)]
    dump_ast: bool,

    // Hide non-fatal warnings (`project` and `resolve`) in CLI output.
    #[arg(long, default_value_t = false)]
    suppress_warnings: bool,
}


fn main() -> Result<()> {
    let args = OilCompilerArgs::parse();

    // Expand CLI inputs to a deduplicated list of `.oil` files.
    let files = collect_oil_files(&args.source)?;
    if files.is_empty() {
        return Err(anyhow::anyhow!(
            "no .oil files found from provided --source inputs"
        ));
    }

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut inputs = Vec::new();
    let mut source_by_id: HashMap<String, (PathBuf, String)> = HashMap::new();

    // Compile each file independently to allow batch diagnostics.
    for file in files {
        println!("[oilc] reading source file {}", file.display());
        let src = match fs::read_to_string(&file)
            .with_context(|| format!("failed to read source file: {}", file.display()))
        {
            Ok(s) => s,
            Err(e) => {
                failed += 1;
                eprintln!("[oilc] error: {e}");
                continue;
            }
        };

        let id = file.to_string_lossy().to_string();
        source_by_id.insert(id.clone(), (file.clone(), src.clone()));
        inputs.push(CompileUnitInput { id, source: src });
    }

    let config = CompilerConfig; // TODO: what should this be?
    let compiled = compile_many(inputs, &config);

    if !args.suppress_warnings {
        for d in &compiled.project_diagnostics {
            eprintln!("[oilc] warning [{}] {}", d.stage, d.message);
        }
    }

    for unit in compiled.units {
        let Some((file, src)) = source_by_id.get(&unit.id) else {
            continue;
        };

        if let Some(output) = unit.output {
            succeeded += 1;
            println!(
                "[oilc] tokenized {} tokens from {}",
                output.tokens.len(),
                file.display()
            );

            // Non-fatal diagnostics (resolver/prelude warnings) are emitted here.
            if !args.suppress_warnings {
                for d in &output.diagnostics {
                    eprintln!("{}", format_diagnostic(file, src, d, "warning"));
                }
            }

            if args.dump_tokens {
                println!("--- tokens: {} ---", file.display());
                for tok in &output.tokens {
                    println!("{:?} @ {:?}", tok.kind, tok.span);
                }
            }

            if args.dump_ast {
                println!("--- ast: {} ---", file.display());
                if let Some(program) = &output.program {
                    println!("{:#?}", program);
                } else {
                    println!("<no AST produced>");
                }
            }
        } else {
            failed += 1;
            // Fatal diagnostics (lex/parse/schema/prelude load failures).
            print_error_diagnostics(file, src, &unit.errors);
        }
    }

    println!("[oilc] done | succeeded={} failed={}", succeeded, failed);
    if failed > 0 {
        return Err(anyhow::anyhow!("one or more sources failed"));
    }

    Ok(())
}

// Helper to render fatal diagnostics consistently.
fn print_error_diagnostics(file: &Path, src: &str, diagnostics: &[Diagnostic]) {
    eprintln!("[oilc] error in {}:", file.display());
    for d in diagnostics {
        eprintln!("{}", format_diagnostic(file, src, d, "error"));
    }
}

// Collect all `.oil` files from user-provided paths.
// Accepts both files and directories (directories are recursive).
fn collect_oil_files(inputs: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for input in inputs {
        let path = PathBuf::from(input);
        if !path.exists() {
            return Err(anyhow::anyhow!("source path does not exist: {}", input));
        }

        if path.is_file() {
            if is_oil_file(&path) {
                files.push(path);
            }
            continue;
        }

        if path.is_dir() {
            collect_from_dir(&path, &mut files)?;
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

// Depth-first recursive directory walk.
fn collect_from_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();

        if path.is_dir() {
            collect_from_dir(&path, out)?;
        } else if path.is_file() && is_oil_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

// File extension filter used by collection helpers.
fn is_oil_file(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("oil"))
        .unwrap_or(false)
}
