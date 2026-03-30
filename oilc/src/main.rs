use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use oilc::{
    compile_many, diagnostics::format_diagnostic, CompileUnitInput, CompilerConfig, Diagnostic,
};
use serde_json::json;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputMode {
    Check,
    Ast,
    Mir,
    RuntimeIr,
    Cypher,
    Epl,
    Codegen,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum DiagnosticsFormat {
    Text,
    Json,
}

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

    // Disable typecheck stage.
    #[arg(long, default_value_t = false)]
    no_typecheck: bool,

    // Disable MIR stage.
    #[arg(long, default_value_t = false)]
    no_mir: bool,

    // Disable backend generation stage.
    #[arg(long, default_value_t = false)]
    no_codegen: bool,

    // Promote resolver warnings to errors.
    #[arg(long, default_value_t = false)]
    fail_on_resolve_warning: bool,

    // Promote typecheck warnings to errors.
    #[arg(long, default_value_t = false)]
    fail_on_type_warning: bool,

    // Promote MIR validation warnings to errors.
    #[arg(long, default_value_t = false)]
    fail_on_mir_warning: bool,

    // Output mode.
    #[arg(long, value_enum, default_value_t = OutputMode::Check)]
    mode: OutputMode,

    // Diagnostics output format.
    #[arg(long, value_enum, default_value_t = DiagnosticsFormat::Text)]
    diagnostics_format: DiagnosticsFormat,

    // Optional path to write runtime IR artifact JSON.
    #[arg(long)]
    emit_runtime_ir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = OilCompilerArgs::parse();
    let emit_runtime_ir_requested = args.emit_runtime_ir.is_some();
    let json_diagnostics = matches!(args.diagnostics_format, DiagnosticsFormat::Json);
    let mode_requires_mir = matches!(
        args.mode,
        OutputMode::Mir
            | OutputMode::RuntimeIr
            | OutputMode::Cypher
            | OutputMode::Epl
            | OutputMode::Codegen
    ) || emit_runtime_ir_requested;
    let mode_requires_codegen = matches!(
        args.mode,
        OutputMode::Cypher | OutputMode::Epl | OutputMode::Codegen
    );
    if mode_requires_mir && args.no_mir {
        return Err(anyhow::anyhow!(
            "--mode {:?} requires MIR; remove --no-mir",
            args.mode
        ));
    }
    if mode_requires_codegen && args.no_codegen {
        return Err(anyhow::anyhow!(
            "--mode {:?} requires codegen; remove --no-codegen",
            args.mode
        ));
    }

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
    let mut json_units = Vec::new();
    let mut runtime_ir_units: Vec<(String, oilc::RuntimeProgram)> = Vec::new();

    // Compile each file independently to allow batch diagnostics.
    for file in files {
        if !json_diagnostics {
            println!("[oilc] reading source file {}", file.display());
        }
        let src = match fs::read_to_string(&file)
            .with_context(|| format!("failed to read source file: {}", file.display()))
        {
            Ok(s) => s,
            Err(e) => {
                failed += 1;
                if json_diagnostics {
                    json_units.push(json!({
                        "id": file.to_string_lossy().to_string(),
                        "file": file.display().to_string(),
                        "status": "io_error",
                        "token_count": 0,
                        "diagnostics": [{
                            "stage": "io",
                            "is_error": true,
                            "message": e.to_string(),
                            "span": null
                        }],
                    }));
                } else {
                    eprintln!("[oilc] error: {e}");
                }
                continue;
            }
        };

        let id = file.to_string_lossy().to_string();
        source_by_id.insert(id.clone(), (file.clone(), src.clone()));
        inputs.push(CompileUnitInput { id, source: src });
    }

    let config = CompilerConfig {
        run_typecheck: !args.no_typecheck,
        run_mir: !args.no_mir || mode_requires_mir,
        run_codegen: !args.no_codegen || mode_requires_codegen,
        fail_on_resolve_warning: args.fail_on_resolve_warning,
        fail_on_type_warning: args.fail_on_type_warning,
        fail_on_mir_warning: args.fail_on_mir_warning,
        ..CompilerConfig::default()
    };
    let compiled = compile_many(inputs, &config);

    if !json_diagnostics {
        for d in compiled.project_diagnostics.iter().rev() {
            if d.is_error {
                eprintln!("[oilc] error [{}] {}", d.stage, d.message);
            } else if !args.suppress_warnings {
                eprintln!("[oilc] warning [{}] {}", d.stage, d.message);
            }
        }
    }

    for unit in compiled.units {
        let Some((file, src)) = source_by_id.get(&unit.id) else {
            continue;
        };

        if let Some(output) = unit.output {
            let has_semantic_error = output.diagnostics.iter().any(|d| d.is_error);
            if has_semantic_error {
                failed += 1;
            } else {
                succeeded += 1;
                if let Some(runtime_ir) = &output.runtime_ir {
                    runtime_ir_units.push((unit.id.clone(), runtime_ir.clone()));
                }
            }
            if json_diagnostics {
                let diags = output
                    .diagnostics
                    .iter()
                    .map(|d| {
                        json!({
                            "stage": d.stage,
                            "is_error": d.is_error,
                            "message": d.message,
                            "span": d.span.as_ref().map(|s| json!({"start": s.start, "end": s.end}))
                        })
                    })
                    .collect::<Vec<_>>();
                json_units.push(json!({
                    "id": unit.id,
                    "file": file.display().to_string(),
                    "status": if has_semantic_error { "failed" } else { "ok" },
                    "token_count": output.tokens.len(),
                    "diagnostics": diags,
                }));
            } else {
                println!(
                    "[oilc] tokenized {} tokens from {}",
                    output.tokens.len(),
                    file.display()
                );

                for d in output.diagnostics.iter().rev() {
                    if d.is_error {
                        eprintln!("{}", format_diagnostic(file, src, d, "error"));
                    } else if !args.suppress_warnings {
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

                render_mode_output(args.mode, file, &output);
            }
        } else {
            failed += 1;
            // Fatal diagnostics (lex/parse/schema/prelude load failures).
            if json_diagnostics {
                let diags = unit
                    .errors
                    .iter()
                    .map(|d| {
                        json!({
                            "stage": d.stage,
                            "is_error": d.is_error,
                            "message": d.message,
                            "span": d.span.as_ref().map(|s| json!({"start": s.start, "end": s.end}))
                        })
                    })
                    .collect::<Vec<_>>();
                json_units.push(json!({
                    "id": unit.id,
                    "file": file.display().to_string(),
                    "status": "failed",
                    "token_count": 0,
                    "diagnostics": diags,
                }));
            } else {
                print_error_diagnostics(file, src, &unit.errors);
            }
        }
    }

    if let Some(path) = &args.emit_runtime_ir {
        write_runtime_ir_artifact(path, &runtime_ir_units)?;
        if !json_diagnostics {
            println!(
                "[oilc] wrote runtime-ir artifact for {} unit(s) to {}",
                runtime_ir_units.len(),
                path.display()
            );
        }
    }

    if json_diagnostics {
        let project_diagnostics = compiled
            .project_diagnostics
            .iter()
            .map(|d| {
                json!({
                    "stage": d.stage,
                    "is_error": d.is_error,
                    "message": d.message,
                    "span": d.span.as_ref().map(|s| json!({"start": s.start, "end": s.end}))
                })
            })
            .collect::<Vec<_>>();
        let report = json!({
            "summary": {
                "succeeded": succeeded,
                "failed": failed,
                "mode": format!("{:?}", args.mode).to_lowercase(),
            },
            "project_diagnostics": project_diagnostics,
            "units": json_units,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|_| "{\"error\":\"failed to serialize diagnostics\"}".to_string())
        );
        if failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!("[oilc] done | succeeded={} failed={}", succeeded, failed);
    if failed > 0 {
        return Err(anyhow::anyhow!("one or more sources failed"));
    }

    Ok(())
}

fn write_runtime_ir_artifact(path: &Path, units: &[(String, oilc::RuntimeProgram)]) -> Result<()> {
    let payload = if units.len() == 1 {
        serde_json::to_value(&units[0].1)?
    } else {
        json!({
            "version": 1,
            "units": units.iter().map(|(id, program)| {
                json!({
                    "id": id,
                    "program": program
                })
            }).collect::<Vec<_>>()
        })
    };

    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(path, serialized)
        .with_context(|| format!("failed to write runtime-ir artifact to {}", path.display()))?;
    Ok(())
}

// Renders human-readable CLI output for a single compiled file based on the selected mode.
// `check` mode intentionally prints nothing; other modes print the available stage artifact
// (AST, MIR, runtime IR, or generated code) with a fallback message when that artifact is missing.
fn render_mode_output(mode: OutputMode, file: &Path, output: &oilc::CompileOutput) {
    match mode {
        OutputMode::Check => {}
        OutputMode::Ast => {
            println!("--- mode=ast: {} ---", file.display());
            if let Some(program) = &output.program {
                println!("{:#?}", program);
            } else {
                println!("<no AST produced>");
            }
        }
        OutputMode::Mir => {
            println!("--- mode=mir: {} ---", file.display());
            if let Some(mir) = &output.mir {
                println!("{:#?}", mir);
            } else {
                println!("<no MIR produced>");
            }
        }
        OutputMode::RuntimeIr => {
            println!("--- mode=runtime-ir: {} ---", file.display());
            if let Some(runtime_ir) = &output.runtime_ir {
                match serde_json::to_string_pretty(runtime_ir) {
                    Ok(json) => println!("{json}"),
                    Err(e) => println!("{{\"error\":\"failed to serialize runtime-ir: {e}\"}}"),
                }
            } else {
                println!("<no runtime IR produced>");
            }
        }
        OutputMode::Cypher => {
            println!("--- mode=cypher: {} ---", file.display());
            if let Some(codegen) = &output.codegen {
                for artifact in &codegen.cypher.artifacts {
                    println!("### {}", artifact.trigger_name);
                    println!("{}", artifact.cypher);
                }
            } else {
                println!("<no codegen produced>");
            }
        }
        OutputMode::Epl => {
            println!("--- mode=epl: {} ---", file.display());
            if let Some(codegen) = &output.codegen {
                for artifact in &codegen.epl.artifacts {
                    println!("### {}", artifact.function_name);
                    if let Some(path) = &artifact.shared_object_path {
                        println!("// shared_object: {path}");
                    }
                    if let Some(err) = &artifact.compile_error {
                        println!("// compile_error:");
                        println!("{err}");
                    }
                    println!("{}", artifact.source);
                }
            } else {
                println!("<no codegen produced>");
            }
        }
        OutputMode::Codegen => {
            println!("--- mode=codegen: {} ---", file.display());
            if let Some(codegen) = &output.codegen {
                for artifact in &codegen.cypher.artifacts {
                    println!("### cypher: {}", artifact.trigger_name);
                    println!("{}", artifact.cypher);
                }
                for artifact in &codegen.epl.artifacts {
                    println!("### epl: {}", artifact.function_name);
                    if let Some(path) = &artifact.shared_object_path {
                        println!("// shared_object: {path}");
                    }
                    if let Some(err) = &artifact.compile_error {
                        println!("// compile_error:");
                        println!("{err}");
                    }
                    println!("{}", artifact.source);
                }
            } else {
                println!("<no codegen produced>");
            }
        }
    }
}

// Helper to render fatal diagnostics consistently.
fn print_error_diagnostics(file: &Path, src: &str, diagnostics: &[Diagnostic]) {
    eprintln!("[oilc] error in {}:", file.display());
    for d in diagnostics.iter().rev() {
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
    for entry in
        fs::read_dir(dir).with_context(|| format!("failed to read directory: {}", dir.display()))?
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
