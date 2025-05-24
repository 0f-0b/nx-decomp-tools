use addr2line::fallible_iterator::FallibleIterator;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use capstone as cs;
use capstone::arch::BuildsCapstone;
use colored::*;
use goblin::elf::sym::STT_FUNC;
use itertools::Itertools;
use lexopt::prelude::*;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic;
use viking::checks::FunctionChecker;
use viking::checks::Mismatch;
use viking::elf;
use viking::functions;
use viking::functions::get_file_list_path;
use viking::functions::Status;
use viking::repo;
use viking::ui;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Default)]
struct Args {
    function: Option<String>,
    version: Option<String>,
    always_diff: bool,
    warnings_as_errors: bool,
    check_placement: bool,
    print_help: bool,
    other_args: Vec<String>,
}

impl Args {
    fn get_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

fn main() -> Result<()> {
    ui::init_prompt_settings();

    let args = parse_args()?;

    if args.print_help {
        print_help()?;
        return Ok(());
    }

    let version = args.get_version();

    let orig_elf = elf::load_orig_elf(version).context("failed to load original ELF")?;
    let decomp_elf = elf::load_decomp_elf(version).context("failed to load decomp ELF")?;

    // Load these in parallel.
    let mut decomp_symtab = None;
    let mut decomp_glob_data_table = None;
    let mut file_list = None;

    rayon::scope(|s| {
        s.spawn(|_| decomp_symtab = Some(elf::make_symbol_map_by_name(&decomp_elf)));
        s.spawn(|_| decomp_glob_data_table = Some(elf::build_glob_data_table(&decomp_elf)));
        s.spawn(|_| {
            file_list = Some(functions::parse_file_list(
                get_file_list_path(version).as_path(),
            ));
        });
    });

    let decomp_symtab = decomp_symtab
        .unwrap()
        .context("failed to make symbol map")?;

    let decomp_glob_data_table = decomp_glob_data_table
        .unwrap()
        .context("failed to make global data table")?;

    let file_list = file_list.unwrap().context("failed to load file list")?;

    let functions = functions::get_functions(&file_list);

    let checker = FunctionChecker::new(
        &orig_elf,
        &decomp_elf,
        &decomp_symtab,
        decomp_glob_data_table,
        &functions,
        version,
    )
    .context("failed to construct FunctionChecker")?;

    if let Some(func) = &args.function {
        check_single(&checker, &functions, file_list, func, &args)?;
    } else {
        check_all(&checker, file_list, &args)?;
    }

    Ok(())
}

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut args = Args {
        version: repo::get_config().default_version.clone(),
        ..Default::default()
    };

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => {
                args.version = Some(parser.value()?.into_string()?);
            }
            Long("always-diff") => {
                args.always_diff = true;
            }
            Long("warnings-as-errors") => {
                args.warnings_as_errors = true;
            }

            Long("help") | Short('h') => {
                args.print_help = true;
            }

            Long("check-placement") | Short('p') => {
                args.check_placement = true;
            }

            Value(other_val) if args.function.is_none() => {
                args.function = Some(other_val.into_string()?);
            }
            Value(other_val) if args.function.is_some() => {
                args.other_args.push(other_val.into_string()?);
            }
            Long(other_long) => {
                args.other_args.push(format!("--{other_long}"));
                let opt = parser.optional_value();
                if let Some(o) = opt {
                    args.other_args.push(o.into_string()?);
                }
            }
            Short(other_short) => {
                args.other_args.push(format!("-{other_short}"));
            }

            _ => return Err(arg.unexpected()),
        }
    }

    Ok(args)
}

fn print_help() -> Result<()> {
    println!(
"Usage: check [function name] [--version VERSION] [--always-diff] [asm-differ arguments]

Checks if the compiled bytecode of a function matches the assembly found within the game elf. If not, show the differences between them.
If no function name is provided, all functions within the repository function list will be checked.

optional arguments:

 -h, --help             Show this help message and exit
 --version VERSION      Check the function against version VERSION of the game elf
 --always-diff          Show an assembly diff, even if the function matches
 -p, --check-placement      Check that functions are placed in the correct objects and are correctly placed in the header if they are marked as lazy
All further arguments are forwarded onto asm-differ.

asm-differ arguments:"
);

    let differ_path = repo::get_tools_path()?.join("asm-differ").join("diff.py");

    // By default, invoking asm-differ using std::process:Process doesn't seem to allow argparse
    // (the python module asm-differ uses to print its help text) to correctly determine the number of columns in the host terminal.
    // To work around this, we'll detect that for it, and set it manually via the COLUMNS environment variable
    let num_columns = match crossterm::terminal::size() {
        Ok((num_columns, _num_rows)) => num_columns,
        Err(_) => 240,
    };

    let output = std::process::Command::new(&differ_path)
        .current_dir(repo::get_tools_path()?)
        .arg("--help")
        .env("COLUMNS", num_columns.to_string())
        .output()
        .with_context(|| format!("failed to launch asm-differ: {:?}", &differ_path))?;

    let asm_differ_help = String::from_utf8_lossy(&output.stdout);

    let asm_differ_arguments = asm_differ_help
        .split("optional arguments:")
        .collect::<Vec<&str>>()
        .get(1)
        .copied()
        .or_else(|| {
            asm_differ_help
                .split("options:")
                .collect::<Vec<&str>>()
                .get(1)
                .copied()
        })
        .unwrap_or(&asm_differ_help);

    println!("{asm_differ_arguments}");

    Ok(())
}

enum CheckResult {
    // If a function does not match, but is marked as such, return this error to show an appropriate exit message.
    MismatchError,
    // If a function does match, but is marked as mismatching, return this warning to indicate this and fix its status.
    MatchWarn,
    // If a function does not match, but is marked as "not decompiled", return this warning to indicate this and fix its status.
    MismatchWarn,
    // Check result matches the expected value listed in the function table.
    Ok,
}

fn check_function(
    checker: &FunctionChecker,
    cs: &mut capstone::Capstone,
    function: &functions::Info,
    args: &Args,
) -> Result<CheckResult> {
    let name = function.name().as_str();
    let decomp_fn = elf::get_function_by_name(checker.decomp_elf, checker.decomp_symtab, name);

    match function.status {
        Status::NotDecompiled if decomp_fn.is_err() => return Ok(CheckResult::Ok),
        Status::Library => return Ok(CheckResult::Ok),
        _ => (),
    }

    if let Err(error) = decomp_fn {
        ui::print_warning(&format!(
            "couldn't check {}: {}",
            ui::format_symbol_name(name),
            error.to_string().dimmed(),
        ));
        if args.warnings_as_errors {
            return Err(error);
        }
        return Ok(CheckResult::Ok);
    }

    let decomp_fn = decomp_fn.unwrap();

    let get_orig_fn = || {
        elf::get_function(checker.orig_elf, function.offset, function.size as u64).with_context(
            || {
                format!(
                    "failed to get function {} ({}) from the original executable",
                    name,
                    ui::format_address(function.offset),
                )
            },
        )
    };

    match function.status {
        Status::Matching => {
            let orig_fn = get_orig_fn()?;

            let result = checker
                .check(cs, &orig_fn, &decomp_fn)
                .with_context(|| format!("checking {name}"))?;

            if let Some(mismatch) = result {
                let stderr = std::io::stderr();
                let mut lock = stderr.lock();
                ui::print_error_ex(
                    &mut lock,
                    &format!(
                        "function {} is marked as matching but does not match",
                        ui::format_symbol_name(name),
                    ),
                );
                ui::print_detail_ex(&mut lock, &mismatch.to_string());
                return Ok(CheckResult::MismatchError);
            }
        }

        Status::NotDecompiled
        | Status::NonMatchingMinor
        | Status::NonMatchingMajor
        | Status::Wip => {
            let orig_fn = get_orig_fn()?;

            let result = checker
                .check(cs, &orig_fn, &decomp_fn)
                .with_context(|| format!("checking {name}"))?;

            if result.is_none() {
                ui::print_note(&format!(
                    "function {} is marked as {} but matches",
                    ui::format_symbol_name(name),
                    function.status.description(),
                ));
                return Ok(CheckResult::MatchWarn);
            } else if function.status == Status::NotDecompiled {
                ui::print_note(&format!(
                    "function {} is marked as {} but mismatches",
                    ui::format_symbol_name(name),
                    function.status.description(),
                ));
                return Ok(CheckResult::MismatchWarn);
            }
        }

        Status::Library => unreachable!(),
    };

    Ok(CheckResult::Ok)
}

fn check_single(
    checker: &FunctionChecker,
    functions: &Vec<functions::Info>,
    mut file_list: functions::FileListMap,
    fn_to_check: &str,
    args: &Args,
) -> Result<()> {
    let version = args.get_version();
    let function = ui::fuzzy_search_function_interactively(&functions, fn_to_check)?;
    let name = function.name().as_str();

    eprintln!("{}", ui::format_symbol_name(name).bold());

    if matches!(function.status, Status::Library) {
        bail!("L functions should not be decompiled");
    }

    let resolved_name;
    let name = if checker.decomp_symtab.contains_key(name) {
        name
    } else {
        resolved_name = resolve_unknown_fn_interactively(name, checker.decomp_symtab, &functions)?;
        &resolved_name
    };

    let decomp_fn = elf::get_function_by_name(checker.decomp_elf, checker.decomp_symtab, name)
        .with_context(|| {
            format!(
                "failed to get decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    let orig_fn = elf::get_function(checker.orig_elf, function.offset, function.size as u64)?;

    let mut maybe_mismatch = checker
        .check(&mut make_cs()?, &orig_fn, &decomp_fn)
        .with_context(|| format!("checking {name}"))?;

    let mut should_show_diff = args.always_diff;

    if let Some(mismatch) = &maybe_mismatch {
        eprintln!("{}\n{}", "mismatch".red().bold(), &mismatch);
        should_show_diff = true;
    } else {
        eprintln!("{}", "OK".green().bold());
    }

    if should_show_diff {
        show_asm_differ(function, name, &args.other_args, version)?;

        maybe_mismatch =
            rediff_function_after_differ(&functions, &orig_fn, name, &maybe_mismatch, version)
                .context("failed to rediff")?;
    }

    let new_status = match maybe_mismatch {
        Option::None => Status::Matching,
        _ if function.status == Status::NotDecompiled => Status::Wip,
        _ => function.status.clone(),
    };

    // Update the function entry if needed.
    let status_changed = function.status != new_status;
    if status_changed {
        ui::print_note(&format!(
            "changing status from {:?} to {:?}",
            function.status, new_status
        ));
        update_single_function_in_file_list(&mut file_list, function.offset, new_status)?;
        functions::write_functions_to_path(
            functions::get_file_list_path(args.version.as_deref()).as_path(),
            &file_list,
        )?;
    }

    Ok(())
}

fn check_all(
    checker: &FunctionChecker,
    mut file_list: functions::FileListMap,
    args: &Args,
) -> Result<()> {
    let data = &checker.decomp_elf.as_owner().1;
    let data_sync = std::sync::Arc::new(data);

    let failed = atomic::AtomicBool::new(false);
    let functions_changed = atomic::AtomicBool::new(false);

    file_list.par_iter_mut().try_for_each_init(
        || {
            if !args.check_placement {
                return None;
            }
            // addr2line structs can't be safely shared between threads, so we create one context
            // per thread (NOT per iteration)
            let file = addr2line::object::File::parse(&data_sync.clone()).unwrap();
            Some(addr2line::Context::new(&file).unwrap())
        },
        |ctx, (object_name, object)| -> Result<()> {
            for function in object.text_section.iter_mut() {
                let result = CAPSTONE.with(|cs| -> Result<()> {
                    let mut cs = cs.borrow_mut();
                    let status = check_function(checker, &mut cs, function, args).unwrap();
                    match status {
                        CheckResult::MismatchError => {
                            failed.store(true, atomic::Ordering::Relaxed);
                        }
                        CheckResult::MatchWarn => {
                            if function.status != functions::Status::Matching {
                                functions_changed.store(true, atomic::Ordering::Relaxed);
                                function.status = functions::Status::Matching;
                            }
                        }
                        CheckResult::MismatchWarn => {
                            if function.status != functions::Status::NonMatchingMajor {
                                functions_changed.store(true, atomic::Ordering::Relaxed);
                                function.status = functions::Status::NonMatchingMajor;
                            }

                        }
                        CheckResult::Ok => {}
                    }
                    Ok(())
                });

                if result.is_err() {
                    failed.store(true, atomic::Ordering::Relaxed);
                }

                if args.check_placement {
                    let ctx = ctx.as_ref().unwrap();
                    let symbol =
                        elf::find_function_symbol_by_name(&checker.decomp_elf, function.name());
                    let demangled_name = viking::functions::demangle_str(function.name()).unwrap_or(function.name().clone());
                    if let Ok(sym) = symbol {
                        let file_name = ctx
                            .find_frames(sym.st_value)
                            .unwrap()
                            .last()
                            .unwrap()
                            .context("No frame found")?
                            .location.context("No location found")?
                            .file.context("no file found")?.to_owned();
                        if function.lazy {
                            if sym.st_bind() != goblin::elf::sym::STB_WEAK {
                                viking::ui::print_warning(&format!("Found function that is marked as lazy in the file list, but not in the decomp elf: {:?} (maybe move into the header?)", demangled_name));
                            }
                            continue;
                        }
                        if !file_name.ends_with(".cpp") { continue; }
                        let object_path_start_index: usize;
                        if let Some(index) = file_name.find("lib/") {
                            object_path_start_index = index + 4;
                        } else if let Some(index) = file_name.find("src/") {
                            object_path_start_index = index + 4;
                        } else {
                            bail!("Source file should not be located outside of lib and src");
                        }
                        let mut object_path = file_name[object_path_start_index..].to_owned();
                        if let Some(prefixes) = repo::get_config().file_list_removed_prefixes.clone() {
                            for prefix in prefixes {
                                if object_path.starts_with(&prefix) {
                                    object_path = object_path[prefix.len()..].to_owned();
                                }
                            }
                        }

                        if let Some(excluded_folders) = repo::get_config().ignore_placement_in_objects_from.clone() {
                            let mut skip_object = false;
                            for folder in excluded_folders {
                                if object_path.starts_with(&folder) {
                                    skip_object = true;
                                    break;
                                }
                            }
                            if skip_object { continue; }
                        }

                        object_path = object_path.replace(".cpp", ".o");
                            if object_path != *object_name {
                            viking::ui::print_warning(&format!("Found function implemented in the wrong file: {:?}, implemented in: {:?}, should be implemented in: {:?}", demangled_name, object_path, object_name));
                        }
                    }
                }
            }
            Ok(())
        },
    )?;

    if functions_changed.load(atomic::Ordering::Relaxed) {
        functions::write_functions_to_path(
            functions::get_file_list_path(args.version.as_deref()).as_path(),
            &file_list,
        )?;
    }

    if failed.load(atomic::Ordering::Relaxed) {
        bail!("found at least one error");
    } else {
        eprintln!("{}", "OK".green().bold());
        Ok(())
    }
}

#[cold]
#[inline(never)]
fn make_cs() -> Result<cs::Capstone> {
    cs::Capstone::new()
        .arm64()
        .mode(cs::arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .or_else(viking::capstone_utils::translate_cs_error)
}

thread_local! {
    static CAPSTONE: RefCell<cs::Capstone> = RefCell::new(make_cs().unwrap());
}

fn update_single_function_in_file_list(
    file_list: &mut functions::FileListMap,
    address: u64,
    new_status: functions::Status,
) -> Result<()> {
    for object in file_list.values_mut() {
        for function in object.text_section.iter_mut() {
            if function.offset == address {
                function.status = new_status.clone();
                return Ok(());
            }
        }
    }
    bail!(
        "Could not find function to update (with address: {:?})",
        address
    )
}

fn resolve_unknown_fn_interactively(
    ambiguous_name: &str,
    decomp_symtab: &elf::SymbolTableByName,
    functions: &Vec<functions::Info>,
) -> Result<String> {
    let fail = || -> Result<String> {
        bail!("unknown function: {}", ambiguous_name);
    };

    let mut candidates: Vec<_> = decomp_symtab
        .par_iter()
        .filter(|(&name, &sym)| {
            sym.st_type() == STT_FUNC
                && functions::demangle_str(name)
                    .unwrap_or_else(|_| "".to_string())
                    .contains(ambiguous_name)
        })
        .collect();

    // Sort candidates by their name, then deduplicate them based on the address.
    // This ensures that e.g. C1 symbols take precedence over C2 symbols (if both are present).
    candidates.sort_by_key(|(&name, &sym)| (name, sym.st_value));
    candidates.dedup_by_key(|(_, &sym)| sym.st_value);

    // Build a set of functions that have already been decompiled and listed,
    // so we don't suggest them to the user again.
    let decompiled_functions: HashSet<&str> = functions
        .iter()
        .filter(|info| info.is_decompiled())
        .map(|info| info.name().as_str())
        .collect();
    candidates.retain(|(&name, _)| !decompiled_functions.contains(name));

    if candidates.is_empty() {
        return fail();
    }

    ui::clear_terminal();

    if candidates.len() == 1 {
        let prompt = format!(
            "{} is ambiguous; did you mean: {}",
            ambiguous_name,
            ui::format_symbol_name(candidates[0].0),
        );

        let confirmed = inquire::Confirm::new(&prompt).with_default(true).prompt()?;

        if !confirmed {
            return fail();
        }

        Ok(candidates[0].0.to_string())
    } else {
        let prompt = format!("{ambiguous_name} is ambiguous; did you mean:");
        let options = candidates
            .iter()
            .map(|(&name, _)| ui::format_symbol_name(name))
            .collect_vec();

        let selection = inquire::Select::new(&prompt, options)
            .with_starting_cursor(0)
            .raw_prompt()?
            .index;

        Ok(candidates[selection].0.to_string())
    }
}

fn show_asm_differ(
    function: &functions::Info,
    name: &str,
    differ_args: &[String],
    version: Option<&str>,
) -> Result<()> {
    let differ_path = repo::get_tools_path()?.join("asm-differ").join("diff.py");
    let mut cmd = std::process::Command::new(&differ_path);

    cmd.current_dir(repo::get_tools_path()?)
        .arg("-I")
        .arg("-e")
        .arg(name)
        .arg(format!("0x{:016x}", function.offset))
        .arg(format!("0x{:016x}", function.offset + function.size as u64))
        .args(differ_args);

    if let Some(version) = version {
        cmd.args(["--version", version]);
    }

    cmd.status()
        .with_context(|| format!("failed to launch asm-differ: {:?}", &differ_path))?;

    Ok(())
}

fn rediff_function_after_differ(
    functions: &Vec<functions::Info>,
    orig_fn: &elf::Function,
    name: &str,
    previous_check_result: &Option<Mismatch>,
    version: Option<&str>,
) -> Result<Option<Mismatch>> {
    // Reload the decomp ELF because it may have been modified.
    //
    // This can typically happen if the differ was invoked with -mw (auto rebuild);
    // the user could have managed to match a function that used to be non-matching
    // back when the differ was launched.
    let decomp_elf = elf::load_decomp_elf(version).context("failed to reload decomp ELF")?;

    // Also reload the symbol table from the new ELF.
    let decomp_symtab = elf::make_symbol_map_by_name(&decomp_elf)?;
    let decomp_glob_data_table = elf::build_glob_data_table(&decomp_elf)?;

    // And grab the possibly updated function code.
    // Note that the original function doesn't need to be reloaded.
    let decomp_fn =
        elf::get_function_by_name(&decomp_elf, &decomp_symtab, name).with_context(|| {
            format!(
                "failed to reload decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    // Invoke the checker again.
    let checker = FunctionChecker::new(
        orig_fn.owner_elf,
        &decomp_elf,
        &decomp_symtab,
        decomp_glob_data_table,
        functions,
        version,
    )?;

    let maybe_mismatch = checker
        .check(&mut make_cs()?, orig_fn, &decomp_fn)
        .with_context(|| format!("re-checking {name}"))?;

    if previous_check_result.is_some() == maybe_mismatch.is_some() {
        if let Some(mismatch) = &maybe_mismatch {
            eprintln!("{}\n{}", "still mismatching".red().bold(), &mismatch);
        } else {
            eprintln!("{}", "still OK".green().bold());
        }
    } else {
        // Matching status has changed.
        if let Some(mismatch) = &maybe_mismatch {
            eprintln!("{}\n{}", "mismatching now".red().bold(), &mismatch);
        } else {
            eprintln!("{}", "OK now".green().bold());
        }
    }

    Ok(maybe_mismatch)
}
