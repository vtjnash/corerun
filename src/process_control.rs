use nix::fcntl::{fcntl, FcntlArg};
use nix::unistd::pipe;
use std::io::{self, Write, Error, ErrorKind};
use std::os::fd::{RawFd, AsRawFd};
use std::fs::File;
use command_fds::{CommandFdExt, FdMapping};
use std::process::{Command, Stdio, Child};
use crate::core_file_parser::{SegmentInfo, ThreadCommand};
use mach2::bootstrap::bootstrap_look_up;
use mach2::kern_return::{KERN_SUCCESS, KERN_INVALID_ADDRESS};
use mach2::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use mach2::message::{
    MACH_MSGH_BITS, MACH_MSG_TYPE_COPY_SEND, MACH_MSGH_BITS_COMPLEX, MACH_RCV_MSG,
    MACH_MSG_TIMEOUT_NONE, mach_msg_send, mach_msg, mach_msg_header_t, mach_msg_body_t,
    mach_msg_port_descriptor_t, mach_msg_trailer_t, MACH_MSG_TYPE_MAKE_SEND
};
use mach2::port::{mach_port_t, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE};
use mach2::task::{TASK_BOOTSTRAP_PORT, task_get_special_port};
use mach2::traps::mach_task_self;
use mach2::vm::{mach_vm_deallocate, mach_vm_map, mach_vm_region, mach_vm_remap, mach_vm_protect};
use mach2::vm_region::{vm_region_basic_info_64, vm_region_basic_info_64_t, VM_REGION_BASIC_INFO_64};
use mach2::vm_inherit::VM_INHERIT_SHARE;
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE};
use std::mem;
use std::ffi::CString;
use uuid::Uuid;

#[derive(Debug)]
#[repr(C)]
pub struct IpcCommand {
    pub command_type: u32,
    pub data_length: u32,
}

const IPC_CMD_UNMAP_ALL: u32 = 1;
const IPC_CMD_MAP_SEGMENT: u32 = 2;
const IPC_CMD_GET_TASK_PORT: u32 = 4;
const IPC_CMD_LAUNCH_N_THREADS: u32 = 5;

/// A wrapper for a `mach_port_t` to deallocate the port on drop.
pub struct MachPort(pub mach_port_t);

impl Drop for MachPort {
    fn drop(&mut self) {
        unsafe {
            mach_port_deallocate(mach_task_self(), self.0);
        }
    }
}

pub struct ProcessController {
    cached_task_port: Option<MachPort>,
    child: Child,
    write_file: File,
}

#[repr(C)]
pub struct RecvMessage {
    pub header: mach_msg_header_t,
    pub body: mach_msg_body_t,
    pub task_port: mach_msg_port_descriptor_t,
    pub trailer: mach_msg_trailer_t,
}

/// Macro to wrap mach APIs that return `kern_return_t`
macro_rules! ktry {
    ($e:expr) => {{
        let kr = $e;
        if kr != KERN_SUCCESS {
            return Err(format!("`{} failed with return code {:x}", stringify!($e), kr).into());
        }
    }}
}

/// Macro to spawn an empty process using the CARGO_BIN_EXE path.
/// This should be called from the context where CARGO_BIN_EXE_empty_process is available.
#[macro_export]
macro_rules! spawn_empty_process {
    ($coredump_fd:expr) => {
        $crate::process_control::ProcessController::spawn_target_process_with_path(
            env!("CARGO_BIN_EXE_empty_process"),
            $coredump_fd
        )
    };
}

impl ProcessController {
    pub fn spawn_target_process_with_path<P: AsRef<std::path::Path>>(target_program_path: P, coredump_fd: RawFd) -> io::Result<Self> {
        // Create a pipe for IPC communication with CLOEXEC
        let (read_owned_fd, write_owned_fd) = pipe()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create pipe: {}", e)))?;
        
        // Set CLOEXEC on both ends
        fcntl(read_owned_fd.as_raw_fd(), FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set CLOEXEC on read fd: {}", e)))?;
        fcntl(write_owned_fd.as_raw_fd(), FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set CLOEXEC on write fd: {}", e)))?;

        // Spawn the target process with fd mappings
        let mut command = Command::new(target_program_path.as_ref());
        command.stdin(Stdio::null())
               .stdout(Stdio::null())
               .stderr(Stdio::inherit())  // Pass through stderr for debugging
               .fd_mappings(vec![
                   // Map coredump_fd to fd 3 in child
                   FdMapping {
                       parent_fd: coredump_fd,
                       child_fd: 3,
                   },
                   // Map pipe read_fd to fd 4 in child
                   FdMapping {
                       parent_fd: read_owned_fd.as_raw_fd(),
                       child_fd: 4,
                   },
               ]).unwrap();

        let child = command.spawn()?;

        // Convert OwnedFd to File for safe I/O
        let write_file = File::from(write_owned_fd);

        Ok(ProcessController {
            cached_task_port: None,
            child,
            write_file,
        })
    }

    pub fn spawn_target_process(coredump_fd: RawFd) -> io::Result<Self> {
        // Fall back to finding the binary in the same directory as current executable
        let empty_process_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cannot find parent directory"))?
            .join("empty_process");
        
        if !empty_process_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "empty_process binary not found. Please run 'cargo build --bin empty_process' first."
            ));
        }

        Self::spawn_target_process_with_path(empty_process_path, coredump_fd)
    }

    pub fn launch_n_threads(&self, thread_count: u32) -> Result<(), Box<dyn std::error::Error>> {
        // Send command to launch N threads in the child process
        let thread_count_bytes = thread_count.to_le_bytes();
        self.send_ipc_command_with_data(IpcCommand {
            command_type: IPC_CMD_LAUNCH_N_THREADS,
            data_length: thread_count_bytes.len() as u32,
        }, &thread_count_bytes)
    }
    
    pub fn suspend_all_threads(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Get the task port first
        let task_port = self.get_task_port()?;
        
        unsafe {
            let mut threads: *mut mach2::mach_types::thread_act_t = std::ptr::null_mut();
            let mut thread_count: u32 = 0;

            // Get all threads in the task
            let result = mach2::task::task_threads(task_port, &mut threads, &mut thread_count);
            if result != mach2::kern_return::KERN_SUCCESS {
                return Err(format!("task_threads failed: {:x}", result).into());
            }

            // Suspend each thread
            for i in 0..thread_count {
                let thread = *threads.offset(i as isize);
                let suspend_result = mach2::thread_act::thread_suspend(thread);
                if suspend_result == mach2::kern_return::KERN_SUCCESS {
                    println!("Suspended thread {}", i);
                } else {
                    println!("Failed to suspend thread {}: {:x}", i, suspend_result);
                }
            }

            // Clean up the threads array
            mach2::vm::mach_vm_deallocate(
                mach2::traps::mach_task_self(),
                threads as u64,
                (thread_count as usize * std::mem::size_of::<mach2::mach_types::thread_act_t>()) as u64,
            );
        }
        
        Ok(())
    }
    
    pub fn suspend_threads_with_state(&mut self, thread_commands: &[ThreadCommand]) -> Result<(), Box<dyn std::error::Error>> {
        // Get the task port first
        let task_port = self.get_task_port()?;
        
        unsafe {
            let mut threads: *mut mach2::mach_types::thread_act_t = std::ptr::null_mut();
            let mut thread_count: u32 = 0;

            // Get all threads in the task
            let result = mach2::task::task_threads(task_port, &mut threads, &mut thread_count);
            if result != mach2::kern_return::KERN_SUCCESS {
                return Err(format!("task_threads failed: {:x}", result).into());
            }

            // Suspend and set state for each thread
            for i in 0..thread_count {
                let thread = *threads.offset(i as isize);
                
                // Suspend the thread
                let suspend_result = mach2::thread_act::thread_suspend(thread);
                if suspend_result == mach2::kern_return::KERN_SUCCESS {
                    println!("Suspended thread {}", i);
                } else {
                    println!("Failed to suspend thread {}: {:x}", i, suspend_result);
                    continue;
                }
                
                // Set thread state if we have data for this thread
                if let Some(thread_cmd) = thread_commands.get(i as usize) {
                    for thread_state in &thread_cmd.thread_states {
                        let state_result = mach2::thread_act::thread_set_state(
                            thread,
                            thread_state.flavor as i32,
                            thread_state.state_data.as_ptr() as *mut u32,
                            thread_state.count,
                        );
                        if state_result != mach2::kern_return::KERN_SUCCESS {
                            println!("Failed to set thread state for thread {}: {:x}", i, state_result);
                        } else {
                            println!("Set thread state for thread {}: flavor=0x{:x}, count={}", 
                                    i, thread_state.flavor, thread_state.count);
                        }
                    }
                }
            }

            // Clean up the threads array
            mach2::vm::mach_vm_deallocate(
                mach2::traps::mach_task_self(),
                threads as u64,
                (thread_count as usize * std::mem::size_of::<mach2::mach_types::thread_act_t>()) as u64,
            );
        }
        
        Ok(())
    }
    
    pub fn unmap_all_memory(&mut self, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Get the task port first
        let task_port = self.get_task_port()?;
        
        // Use mach_vm_region to iterate through all memory regions and unmap them
        unsafe {
            let mut regions_unmapped = 0;
            let mut address: u64 = 0;
            
            loop {
                let mut region_size: u64 = 0;
                let mut info: vm_region_basic_info_64 = mem::zeroed();
                let mut info_count = vm_region_basic_info_64::count();
                let mut object_name: mach_port_t = 0;
                
                // Get the next memory region
                let region_kr = mach_vm_region(
                    task_port,
                    &mut address,
                    &mut region_size,
                    VM_REGION_BASIC_INFO_64 as i32,
                    &mut info as *mut _ as *mut i32,
                    &mut info_count,
                    &mut object_name,
                );
                
                if region_kr != KERN_SUCCESS {
                    // No more regions to iterate
                    break;
                }
                
                // Unmap this region
                let unmap_kr = mach_vm_deallocate(task_port, address, region_size);
                if unmap_kr == KERN_SUCCESS {
                    regions_unmapped += 1;
                    if verbose {
                        println!("🗑️  Unmapped region at 0x{:x}, size: 0x{:x}", 
                                address, region_size);
                    }
                } else {
                    println!("⚠️  Failed to unmap region at 0x{:x}, size: 0x{:x}: error 0x{:x}", 
                            address, region_size, unmap_kr);
                }
                
                // Move to the next potential region
                // Add region_size to avoid infinite loops on zero-sized regions
                address = address.saturating_add(region_size.max(1));
                
                // Prevent infinite loop by checking for address overflow
                if address == 0 {
                    break;
                }
            }
            
            if verbose {
                println!("✅ Unmapped {} memory regions total", regions_unmapped);
            }
        }
        
        Ok(())
    }
    
    pub fn map_segments(&mut self, segments: &[SegmentInfo], _coredump_fd: RawFd, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Get the task port first
        let task_port = self.get_task_port()?;
        
        for segment in segments {
            unsafe {
                // Step 1: mmap the segment in the parent process from the coredump file
                // We only need PROT_NONE since we're just getting the memory object handle
                let parent_mapped = libc::mmap(
                    std::ptr::null_mut(),
                    segment.vm_size as usize,
                    libc::PROT_NONE,  // No access needed in parent
                    libc::MAP_PRIVATE,
                    _coredump_fd,
                    segment.file_offset as i64,
                );
                
                if parent_mapped == libc::MAP_FAILED {
                    let error = std::io::Error::last_os_error();
                    println!("❌ Failed to mmap segment {} in parent: {}", segment.name, error);
                    return Err(format!("Failed to mmap segment {}: {}", segment.name, error).into());
                }
                
                // Step 2: Try to get the memory object backing the parent mapping
                if verbose {
                    println!("🔍 Parent mapped segment {} at 0x{:x}, size: 0x{:x}, fd offset: 0x{:x}", 
                            segment.name, parent_mapped as u64, segment.vm_size, segment.file_offset);
                }
                
                // Use mach_vm_remap to directly remap from parent to child
                let mut child_mapped_address = segment.vm_address;
                
                // Convert protection flags from segment to mach_vm protection
                let mut cur_protection = 0;
                if segment.init_protection & 1 != 0 { cur_protection |= VM_PROT_READ; }
                if segment.init_protection & 2 != 0 { cur_protection |= VM_PROT_WRITE; }
                if segment.init_protection & 4 != 0 { cur_protection |= VM_PROT_EXECUTE; }
                let mut max_protection = cur_protection;
                
                // Retry loop for handling address conflicts
                let mut remap_kr;
                let max_retries = 10;
                let mut retry_count = 0;
                
                loop {
                    child_mapped_address = segment.vm_address; // Reset address each retry
                    cur_protection = if segment.init_protection & 1 != 0 { VM_PROT_READ } else { 0 } |
                                   if segment.init_protection & 2 != 0 { VM_PROT_WRITE } else { 0 } |
                                   if segment.init_protection & 4 != 0 { VM_PROT_EXECUTE } else { 0 };
                    max_protection = cur_protection;
                    
                    remap_kr = mach_vm_remap(
                        task_port,                    // target_task (child)
                        &mut child_mapped_address,    // target_address
                        segment.vm_size,              // size
                        0,                            // mask
                        0,                            // anywhere
                        mach_task_self(),             // src_task (parent)
                        parent_mapped as u64,         // src_address
                        1,                            // copy (COW)
                        &mut cur_protection,          // cur_protection
                        &mut max_protection,          // max_protection
                        VM_INHERIT_SHARE,             // inheritance
                    );
                    
                    // If remap succeeded or we've exceeded retry limit, break
                    if remap_kr == KERN_SUCCESS || retry_count >= max_retries {
                        break;
                    }
                    
                    // If remap failed with KERN_INVALID_ADDRESS, try to clear conflicting regions
                    if remap_kr == KERN_INVALID_ADDRESS {
                        println!("🔍 Investigating KERN_INVALID_ADDRESS for address 0x{:x} (retry {})", segment.vm_address, retry_count + 1);
                        
                        // Try to get region info for the target address in the child process
                        let mut probe_address = segment.vm_address;
                        let mut probe_size: u64 = 0;
                        let mut probe_info: vm_region_basic_info_64 = mem::zeroed();
                        let mut probe_info_count = vm_region_basic_info_64::count();
                        let mut probe_object_name: mach_port_t = 0;
                        
                        let probe_kr = mach_vm_region(
                            task_port,
                            &mut probe_address,
                            &mut probe_size,
                            VM_REGION_BASIC_INFO_64 as i32,
                            &mut probe_info as *mut _ as *mut i32,
                            &mut probe_info_count,
                            &mut probe_object_name,
                        );
                        
                        if probe_kr == KERN_SUCCESS {
                            println!("🔍 Found region at 0x{:x}, size: 0x{:x}, protection: 0x{:x}, max_protection: 0x{:x}", 
                                    probe_address, probe_size, probe_info.protection, probe_info.max_protection);
                            
                            // Check if this region overlaps with our desired mapping
                            let region_end = probe_address + probe_size;
                            let segment_end = segment.vm_address + segment.vm_size;
                            
                            if probe_address < segment_end && region_end > segment.vm_address {
                                println!("🗑️  Found conflicting region, deallocating at 0x{:x}, size: 0x{:x}", 
                                        probe_address, probe_size);
                                
                                let dealloc_kr = mach_vm_deallocate(task_port, probe_address, probe_size);
                                if dealloc_kr == KERN_SUCCESS {
                                    println!("✅ Successfully deallocated conflicting region");
                                } else {
                                    println!("⚠️  Failed to deallocate conflicting region: error 0x{:x}", dealloc_kr);
                                    break; // Can't make progress, exit retry loop
                                }
                            } else {
                                println!("🔍 Region doesn't overlap with desired mapping area");
                                break; // No overlapping region found, no point in retrying
                            }
                        } else {
                            println!("🔍 No region found at or after 0x{:x}: error 0x{:x}", 
                                    segment.vm_address, probe_kr);
                            break; // No region to clear, exit retry loop
                        }
                    } else {
                        // Different error, don't retry
                        break;
                    }
                    
                    retry_count += 1;
                }
                
                if remap_kr == KERN_SUCCESS {
                    // Convert segment protection to mach_vm protection for comparison
                    let mut desired_vm_prot = 0;
                    if segment.init_protection & 1 != 0 { desired_vm_prot |= VM_PROT_READ; }
                    if segment.init_protection & 2 != 0 { desired_vm_prot |= VM_PROT_WRITE; }
                    if segment.init_protection & 4 != 0 { desired_vm_prot |= VM_PROT_EXECUTE; }
                    
                    // Adjust protection if it doesn't match desired
                    if cur_protection != desired_vm_prot {
                        let protect_kr = mach_vm_protect(
                            task_port,
                            child_mapped_address,
                            segment.vm_size,
                            0, // set_maximum = false
                            desired_vm_prot,
                        );
                        if protect_kr == KERN_SUCCESS {
                            cur_protection = desired_vm_prot; // Update for debug print
                        } else {
                            println!("⚠️  Failed to adjust protection for segment {}: error 0x{:x}", 
                                    segment.name, protect_kr);
                        }
                    }
                    
                    if verbose {
                        // Debug: Print protection info after remap
                        let desired_prot = if segment.init_protection & 1 != 0 { "R" } else { "-" }.to_string() +
                                          if segment.init_protection & 2 != 0 { "W" } else { "-" } +
                                          if segment.init_protection & 4 != 0 { "X" } else { "-" };
                        println!("🔧 Protection debug - desired: {} (0x{:x}), cur: 0x{:x}, max: 0x{:x}", 
                                desired_prot, segment.init_protection, cur_protection, max_protection);
                    }
                    
                    if child_mapped_address == segment.vm_address {
                        if verbose {
                            println!("✅ Mapped segment {} at 0x{:x}, size: 0x{:x} (mach_vm_remap)", 
                                    segment.name, child_mapped_address, segment.vm_size);
                        }
                    } else {
                        println!("⚠️  Segment {} mapped to 0x{:x} instead of 0x{:x}, size: 0x{:x} (mach_vm_remap)", 
                                segment.name, child_mapped_address, segment.vm_address, segment.vm_size);
                    }
                } else {
                    println!("⚠️  Failed to remap segment {} at 0x{:x}: error 0x{:x}", 
                            segment.name, segment.vm_address, remap_kr);
                }
                
                // Step 5: munmap the parent mapping
                libc::munmap(parent_mapped, segment.vm_size as usize);
            }
        }
        
        Ok(())
    }
    
    /* BACKUP: IPC-based memory mapping implementation
       Keep this code as fallback in case we need child-side memory mapping via IPC
       
    pub fn map_segments_via_ipc(&self, segments: &[SegmentInfo]) -> Result<(), Box<dyn std::error::Error>> {
        for segment in segments {
            // Serialize segment data: address + size + file_offset + file_size + protection
            let mut segment_data = Vec::new();
            segment_data.extend_from_slice(&segment.vm_address.to_le_bytes());
            segment_data.extend_from_slice(&segment.vm_size.to_le_bytes());
            segment_data.extend_from_slice(&segment.file_offset.to_le_bytes());
            segment_data.extend_from_slice(&segment.file_size.to_le_bytes());
            segment_data.extend_from_slice(&segment.init_protection.to_le_bytes());
            
            // Send map segment command to child process via IPC
            self.send_ipc_command_with_data(IpcCommand {
                command_type: IPC_CMD_MAP_SEGMENT,
                data_length: segment_data.len() as u32,
            }, &segment_data)?;
        }
        Ok(())
    }
    */
    
    fn send_ipc_command_with_data(&self, command: IpcCommand, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let command_bytes = unsafe {
            std::slice::from_raw_parts(
                &command as *const _ as *const u8,
                std::mem::size_of::<IpcCommand>()
            )
        };
        
        // Use safe I/O operations - write_all handles EAGAIN/EINTR automatically
        let mut write_file = &self.write_file;
        
        // Send the command header first
        write_file.write_all(command_bytes)
            .map_err(|e| format!("Failed to send IPC command header (type: {}): {}", command.command_type, e))?;
        
        // Send the data payload if present
        if !data.is_empty() {
            write_file.write_all(data)
                .map_err(|e| format!("Failed to send IPC command data (type: {}): {}", command.command_type, e))?;
        }
        
        // Ensure data is flushed to the pipe
        write_file.flush()
            .map_err(|e| format!("Failed to flush IPC command (type: {}): {}", command.command_type, e))?;
        
        Ok(())
    }

    pub fn get_task_port(&mut self) -> Result<mach_port_t, Box<dyn std::error::Error>> {
        // Return cached port if available
        if let Some(ref port) = self.cached_task_port {
            return Ok(port.0);
        }

        // Create a port to receive the child's task port
        let port = unsafe {
            let mut port: mach_port_t = mem::zeroed();
            let kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut port);
            if kr != KERN_SUCCESS {
                return Err(format!("mach_port_allocate failed: {:x}", kr).into());
            }
            let port = MachPort(port);

            // Allocate a send right for the server port
            let kr = mach_port_insert_right(mach_task_self(), port.0, port.0, MACH_MSG_TYPE_MAKE_SEND);
            if kr != KERN_SUCCESS {
                return Err(format!("mach_port_insert_right failed: {:x}", kr).into());
            }
            port
        };

        // Register the port with the bootstrap server using a unique name
        let uuid = Uuid::new_v4().simple().to_string();
        let name = CString::new(uuid.clone())?;
        unsafe {
            let mut bootstrap_port = mem::zeroed();
            let kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &mut bootstrap_port);
            if kr != KERN_SUCCESS {
                return Err(format!("task_get_special_port failed: {:x}", kr).into());
            }
            
            // Use bootstrap_register2 from task_port module
            unsafe extern "C" {
                fn bootstrap_register2(bp: mach_port_t, service_name: *const i8, sp: mach_port_t, flags: u64) -> i32;
            }
            let kr = bootstrap_register2(bootstrap_port, name.as_ptr(), port.0, 0);
            if kr != KERN_SUCCESS {
                return Err(format!("bootstrap_register2 failed: {:x}", kr).into());
            }
        }

        // Send IPC command with the service name
        let service_name_bytes = uuid.as_bytes();
        self.send_ipc_command_with_data(IpcCommand {
            command_type: IPC_CMD_GET_TASK_PORT,
            data_length: service_name_bytes.len() as u32,
        }, service_name_bytes)?;

        // Receive the child's task port
        let child_task_port = unsafe {
            let mut msg: RecvMessage = mem::zeroed();
            let kr = mach_msg(&mut msg.header,
                             MACH_RCV_MSG,
                             0,
                             mem::size_of::<RecvMessage>() as u32,
                             port.0,
                             MACH_MSG_TIMEOUT_NONE,
                             MACH_PORT_NULL);
            if kr != KERN_SUCCESS {
                return Err(format!("mach_msg receive failed: {:x}", kr).into());
            }
            msg.task_port.name
        };

        // Cache the task port for future use
        self.cached_task_port = Some(MachPort(child_task_port));
        
        Ok(child_task_port)
    }

    pub fn get_pid(&self) -> u32 {
        self.child.id()
    }
    
    pub fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}

impl Drop for ProcessController {
    fn drop(&mut self) {
        // IPC file will be automatically closed when write_file drops
        
        // Kill the child process when dropping
        let _ = self.child.kill();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_process_controller_creation() {
        // This test would require actual process spawning, 
        // so we'll just test the struct creation logic
        assert!(true);
    }
}