use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

// Import the main crate modules
use corerun::core_file_parser::CoreFileParser;
// ProcessController is now accessed via macro
use corerun::memory_manager::MemoryManager;

fn apply_entitlements_to_empty_process() -> Result<(), Box<dyn std::error::Error>> {
    // Get the path to the empty_process binary
    let empty_process_path = env!("CARGO_BIN_EXE_empty_process");
    
    // Check if codesign is available
    let codesign_check = Command::new("which")
        .arg("codesign")
        .output();
    
    if codesign_check.is_err() || !codesign_check.unwrap().status.success() {
        println!("⚠️  codesign not available - skipping entitlements");
        return Ok(());
    }
    
    // Apply entitlements to the empty_process binary
    let entitlements_path = std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| format!("{}/entitlements.plist", dir))
        .unwrap_or_else(|_| "entitlements.plist".to_string());
    
    println!("Applying entitlements to empty_process binary...");
    let result = Command::new("codesign")
        .args([
            "--entitlements", &entitlements_path,
            "--force",
            "--sign", "-",
            empty_process_path
        ])
        .output()?;
    
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("Failed to apply entitlements: {}", stderr).into());
    }
    
    println!("✓ Entitlements applied successfully to empty_process");
    
    // Verify entitlements were applied
    let verify_result = Command::new("codesign")
        .args([
            "--display",
            "--entitlements", "-",
            empty_process_path
        ])
        .output();
    
    if let Ok(output) = verify_result {
        if output.status.success() {
            println!("✓ Entitlements verified");
        }
    }
    
    Ok(())
}

fn setup_core_dumps() -> Result<(), Box<dyn std::error::Error>> {
    // Enable unlimited core dumps
    unsafe {
        let result = libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            },
        );
        if result != 0 {
            return Err(format!("Failed to set core dump limit: {}", 
                             std::io::Error::last_os_error()).into());
        }
    }

    // On macOS, core dumps are typically generated in the current directory
    // or in /cores/ directory - the path cannot be changed programmatically
    println!("Core dump limit set to unlimited");
    println!("Core dumps will be generated in system default locations");
    
    Ok(())
}

fn wait_for_core_dump(temp_dir: &PathBuf, pid: u32, timeout_secs: u64) -> Option<PathBuf> {
    let start_time = std::time::Instant::now();
    
    // On macOS, core dumps can be generated in various locations
    let possible_locations = vec![
        temp_dir.join(format!("core.{}", pid)),
        PathBuf::from(format!("core.{}", pid)),
        PathBuf::from(format!("/cores/core.{}", pid)),
        temp_dir.join("core"),
        PathBuf::from("core"),
    ];
    
    while start_time.elapsed().as_secs() < timeout_secs {
        for location in &possible_locations {
            if location.exists() {
                return Some(location.clone());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    None
}

#[test]
fn test_core_dump_generation_and_loading() -> Result<(), Box<dyn std::error::Error>> {
    // Apply entitlements to empty_process binary first
    apply_entitlements_to_empty_process()?;
    
    // Create temporary directory for core dumps
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().to_path_buf();
    
    // Setup core dumps
    setup_core_dumps()?;
    
    // Use the CARGO_BIN_EXE environment variable to find the empty_process binary
    let empty_process_path = env!("CARGO_BIN_EXE_empty_process");
    
    // Spawn the empty process
    let mut child = Command::new(empty_process_path)
        .spawn()?;
    
    let pid = child.id();
    println!("Spawned target process with PID: {}", pid);
    
    // Give the process a moment to start
    thread::sleep(Duration::from_millis(500));
    
    // Kill the process with SIGQUIT to generate a core dump
    signal::kill(Pid::from_raw(pid as i32), Signal::SIGQUIT)?;
    
    // Wait for the process to exit
    let exit_status = child.wait()?;
    println!("Process exited with status: {:?}", exit_status);
    
    // Wait for core dump to be generated
    let core_dump_path = wait_for_core_dump(&temp_path, pid, 10)
        .ok_or("Core dump was not generated within timeout")?;
    
    println!("Core dump generated: {:?}", core_dump_path);
    
    // Test loading the core dump
    let coredump_data = std::fs::read(&core_dump_path)?;
    let parser = CoreFileParser::new(&coredump_data)?;
    let segments = parser.parse_segments()?;
    
    println!("Successfully parsed {} segments from core dump", segments.len());
    
    // Verify we have some reasonable segments
    assert!(!segments.is_empty(), "Core dump should contain at least one segment");
    
    // Look for typical segments like TEXT, DATA, etc.
    let segment_names: Vec<&str> = segments.iter().map(|s| s.name.as_str()).collect();
    println!("Found segments: {:?}", segment_names);
    
    // Test that we can open the core dump for memory operations
    let coredump_file = File::open(&core_dump_path)?;
    let _memory_manager = MemoryManager::new(
        0, // dummy task port for testing
        coredump_file.as_raw_fd()
    );
    
    // Just verify the memory manager was created successfully
    // (We can't test actual memory mapping without a real target process)
    println!("Memory manager created successfully");
    
    // Clean up - remove the core dump
    fs::remove_file(&core_dump_path)?;
    println!("Core dump cleaned up");
    
    Ok(())
}

#[test]
fn test_empty_process_with_fd3() -> Result<(), Box<dyn std::error::Error>> {
    // Apply entitlements to empty_process binary first
    apply_entitlements_to_empty_process()?;
    
    // Create a temporary file to pass as fd 3
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();
    
    // Write some test data to the file
    fs::write(temp_path, b"test coredump data")?;
    
    // Open the file to get a file descriptor
    let coredump_file = File::open(temp_path)?;
    
    // Test spawning the empty process with fd 3 using the macro
    let process_controller = corerun::spawn_empty_process!(coredump_file.as_raw_fd())?;
    
    println!("Successfully spawned empty process with PID: {}", process_controller.get_pid());
    
    // Give it a moment to start
    thread::sleep(Duration::from_millis(100));
    
    // Test suspending threads (should work better with entitlements)
    match process_controller.suspend_all_threads() {
        Ok(_) => println!("✓ Successfully suspended all threads"),
        Err(e) => println!("Failed to suspend threads: {}", e),
    }
    
    // The process will be cleaned up when ProcessController is dropped
    Ok(())
}

#[test] 
fn test_process_controller_fallback() -> Result<(), Box<dyn std::error::Error>> {
    // Test the fallback method that looks for empty_process in the same directory
    // This test will fail if the binary isn't built, which is expected
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();
    fs::write(temp_path, b"test coredump data")?;
    let coredump_file = File::open(temp_path)?;
    
    // This will likely fail due to binary not being in the right location, but we test the code path
    match corerun::process_control::ProcessController::spawn_target_process(coredump_file.as_raw_fd()) {
        Ok(controller) => {
            println!("Fallback method worked, PID: {}", controller.get_pid());
        },
        Err(e) => {
            println!("Fallback method failed as expected: {}", e);
            assert!(e.to_string().contains("empty_process binary not found"));
        }
    }
    
    Ok(())
}

#[test]
fn test_segment_parsing() -> Result<(), Box<dyn std::error::Error>> {
    // Use the CARGO_BIN_EXE environment variable to find the empty_process binary
    let empty_process_path = env!("CARGO_BIN_EXE_empty_process");
    
    let binary_data = std::fs::read(&empty_process_path)?;
    let parser = CoreFileParser::new(&binary_data)?;
    let segments = parser.parse_segments()?;
    
    // Verify we can parse segments from a regular binary
    assert!(!segments.is_empty(), "Binary should contain segments");
    
    for segment in &segments {
        println!("Segment: {} - addr: 0x{:x}, size: 0x{:x}, offset: 0x{:x}",
                 segment.name, segment.vm_address, segment.vm_size, segment.file_offset);
        
        // Basic sanity checks
        assert!(segment.vm_size > 0, "Segment size should be positive");
        // Note: __PAGEZERO segment has address 0, which is valid
    }
    
    Ok(())
}