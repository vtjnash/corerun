use clap::{Arg, Command};
use memmap2::MmapOptions;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::process;

pub mod mach2_thread_status;
pub mod core_file_parser;
pub mod memory_manager;
pub mod process_control;

use core_file_parser::CoreFileParser;
use process_control::ProcessController;

/// Main entry point for the corerun application.
///
/// This function implements a core dump runner that recreates process memory
/// from MachO files by parsing segments and mapping them into a new process.
///
/// Note: To generate coredumps on macOS, the target process needs the
/// "com.apple.security.get-task-allow" entitlement. This is automatically
/// granted for debug builds but may need to be explicitly added for release builds.
fn main() {
    let matches = Command::new("corerun")
        .author("Jameson Nash <vtjnash@gmail.com>")
        .version("0.1.0")
        .about("A macOS core dump runner that recreates process memory from MachO files")
        .arg(
            Arg::new("coredump")
                .help("Path to the MachO coredump file to run")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Turn on verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let coredump_path = matches.get_one::<String>("coredump").unwrap();

    if verbose {
        println!("Verbose mode enabled");
        println!("Using coredump file: {}", coredump_path);
    }

    // Step 1: Parse the core dump file
    if verbose {
        println!("Parsing core dump file...");
    }

    // Memory map the core dump file for efficient access
    let coredump_file = match File::open(coredump_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "Error: Failed to open coredump file '{}': {}",
                coredump_path, e
            );
            process::exit(1);
        }
    };

    let coredump_mmap = match unsafe { MmapOptions::new().map_copy(&coredump_file) } {
        Ok(mmap) => mmap,
        Err(e) => {
            eprintln!(
                "Error: Failed to mmap coredump file '{}': {}",
                coredump_path, e
            );
            process::exit(1);
        }
    };

    let parser = match CoreFileParser::new(&coredump_mmap) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Error: Failed to parse coredump file '{}': {}",
                coredump_path, e
            );
            process::exit(1);
        }
    };

    let segments = match parser.parse_segments() {
        Ok(segments) => segments,
        Err(e) => {
            eprintln!("Error: Failed to parse core dump segments: {}", e);
            process::exit(1);
        }
    };

    let thread_commands = match parser.parse_thread_states() {
        Ok(cmds) => cmds,
        Err(e) => {
            eprintln!("Error: Failed to parse thread commands: {}", e);
            process::exit(1);
        }
    };

    if verbose {
        println!("Core dump file type: {:?}", parser.get_kind());
        println!("Entry point: 0x{:x}", parser.get_entry_point());

        println!("Found {} segments:", segments.len());
        for segment in &segments {
            println!(
                "  {} - addr: 0x{:x}, size: 0x{:x}, offset: 0x{:x}, prot: max=0x{:x} init=0x{:x}",
                segment.name,
                segment.vm_address,
                segment.vm_size,
                segment.file_offset,
                segment.max_protection,
                segment.init_protection
            );
        }

        println!("Found {} thread commands:", thread_commands.len());
        for (i, thread_cmd) in thread_commands.iter().enumerate() {
            println!(
                "  Thread command {}: {} thread states",
                i,
                thread_cmd.thread_states.len()
            );
            for (j, state) in thread_cmd.thread_states.iter().enumerate() {
                println!("  State {}:", j);
                print!("{}", parser.format_thread_state_verbose(state));
            }
        }
    }

    // Step 3: Spawn the target process
    if verbose {
        println!("Spawning target process...");
    }

    let mut process_controller =
        match ProcessController::spawn_target_process(coredump_file.as_raw_fd()) {
            Ok(pc) => pc,
            Err(e) => {
                eprintln!("Error: Failed to spawn target process: {}", e);
                process::exit(1);
            }
        };

    // Step 3.5: Launch required number of threads if we have thread commands
    if !thread_commands.is_empty() {
        let thread_count = thread_commands.len() as u32 - 1;
        if verbose {
            println!("Launching {} threads in target process...", thread_count);
        }

        if let Err(e) = process_controller.launch_n_threads(thread_count) {
            eprintln!("Error: Failed to launch threads: {}", e);
            process::exit(1);
        }
    }

    // Step 3.6: Get task port for memory operations
    if verbose {
        println!("Retrieving task port...");
    }

    let child_pid = process_controller.get_pid();
    println!("Target process spawned with PID: {}", child_pid);

    // Get task port - this will now work with the full IPC implementation
    match process_controller.get_task_port() {
        Ok(task_port) => {
            if verbose {
                println!("Target process task_port: {}", task_port);

                // Verify task_port corresponds to the correct PID
                unsafe extern "C" {
                    fn pid_for_task(
                        task: mach2::port::mach_port_t,
                        pid: *mut libc::c_int,
                    ) -> mach2::kern_return::kern_return_t;
                }

                unsafe {
                    let mut extracted_pid: libc::c_int = 0;
                    let kr = pid_for_task(task_port, &mut extracted_pid);
                    if kr == mach2::kern_return::KERN_SUCCESS {
                        if extracted_pid as u32 == child_pid {
                            println!(
                                "✅ Task port verification successful: pid_for_task({}) == {}",
                                task_port, extracted_pid
                            );
                        } else {
                            println!(
                                "❌ Task port verification failed: pid_for_task({}) returned {} but expected {}",
                                task_port, extracted_pid, child_pid
                            );
                        }
                    } else {
                        println!(
                            "❌ Task port verification failed: pid_for_task returned error 0x{:x}",
                            kr
                        );
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error: Failed to retrieve task port: {}", e);
            process::exit(1);
        }
    }

    // Step 4: Suspend all threads in the target process
    if verbose {
        println!("Suspending target process threads...");
    }

    if let Err(e) = process_controller.suspend_threads_with_state(&thread_commands, verbose) {
        eprintln!("Error: Failed to suspend threads with state: {}", e);
        process::exit(1);
    }

    // Step 5: Unmap existing memory
    if verbose {
        println!("Unmapping existing process memory...");
    }

    if let Err(e) = process_controller.unmap_all_memory(verbose) {
        eprintln!("Error: Failed to unmap memory: {}", e);
        process::exit(1);
    }

    // Step 6: Map segments from the coredump
    if verbose {
        println!("Mapping segments from coredump...");
    }

    if let Err(e) = process_controller.map_segments(&segments, &coredump_mmap, verbose) {
        eprintln!("Error: Failed to map segments: {}", e);
        process::exit(1);
    }

    println!("Successfully recreated process memory from coredump!");
    println!("Target process PID: {}", process_controller.get_pid());
    println!("Process is suspended in background - you can now attach a debugger or analyze it");

    // Wait for the target process to exit
    println!("Waiting for target process to exit...");
    if let Err(e) = process_controller.wait_for_port_death() {
        eprintln!("Error: Failed to wait_for_port_death: {}", e);
        process::exit(1);
    }
    match process_controller.wait() {
        Ok(exit_status) => {
            println!("Target process exited with status: {:?}", exit_status);
        }
        Err(e) => {
            eprintln!("Error waiting for target process: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_app_creation() {
        let app = Command::new("corerun")
            .author("Jameson Nash <vtjnash@gmail.com>")
            .version("0.1.0")
            .about("A Rust command line application");

        assert_eq!(app.get_name(), "corerun");
    }
}
