use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use oilc::{compile, CompilerConfig};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct OilCompilerArgs {
    #[arg(
        short,
        long,
        required = true,
        action = clap::ArgAction::Append,
        num_args = 1
    )]
    source: Vec<String>,

    #[arg(long, default_value_t = false)]
    dump_tokens: bool,

    #[arg(long, default_value_t = false)]
    dump_ast: bool,
}


fn main() -> Result<()> {
    let args = OilCompilerArgs::parse();

    let files = collect_oil_files(&args.source)?;
    if files.is_empty() {
        return Err(anyhow::anyhow!(
            "no .oil files found from provided --source inputs"
        ));
    }

    let mut succeeded = 0usize;
    let mut failed = 0usize;

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

        let config = CompilerConfig; // TODO: what should this be?
        match compile(&src, &config) {
            Ok(output) => {
                succeeded += 1;
                println!(
                    "[oilc] tokenized {} tokens from {}",
                    output.tokens.len(),
                    file.display()
                );

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
            }
            Err(diags) => {
                failed += 1;
                eprintln!("[oilc] error in {}:", file.display());
                for d in diags {
                    if let Some(span) = d.span {
                        eprintln!(
                            "  [{}] {} (span {}..{})",
                            d.stage, d.message, span.start, span.end
                        );
                    } else {
                        eprintln!("  [{}] {}", d.stage, d.message);
                    }
                }
            }
        }
    }

    println!("[oilc] done | succeeded={} failed={}", succeeded, failed);
    if failed > 0 {
        return Err(anyhow::anyhow!("one or more sources failed"));
    }

    Ok(())
}

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

fn is_oil_file(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("oil"))
        .unwrap_or(false)
}
