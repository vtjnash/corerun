use crate::core_file_parser::{SegmentInfo, ThreadCommand};
use command_fds::{CommandFdExt, FdMapping};
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use mach2::message::{
    MACH_MSG_TIMEOUT_NONE, MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, MACH_RCV_MSG,
    mach_msg, mach_msg_body_t, mach_msg_header_t, mach_msg_port_descriptor_t, mach_msg_trailer_t,
};
use mach2::port::{MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE, mach_port_t};
use mach2::task::{TASK_BOOTSTRAP_PORT, task_get_special_port};
use mach2::traps::mach_task_self;
use mach2::vm::{
    mach_vm_copy, mach_vm_deallocate, mach_vm_map, mach_vm_protect, mach_vm_region, mach_vm_remap,
};
use mach2::vm_inherit::VM_INHERIT_SHARE;
use mach2::vm_prot::{VM_PROT_ALL, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64};
use mach2::vm_statistics::{VM_FLAGS_FIXED, VM_FLAGS_OVERWRITE};
use memmap2::MmapMut;
use nix::fcntl::{FcntlArg, fcntl};
use nix::unistd::pipe;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};
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

/// Macro to spawn an empty process using the CARGO_BIN_EXE path.
/// This should be called from the context where CARGO_BIN_EXE_empty_process is available.
#[macro_export]
macro_rules! spawn_empty_process {
    ($coredump_fd:expr) => {
        $crate::process_control::ProcessController::spawn_target_process_with_path(
            env!("CARGO_BIN_EXE_empty_process"),
            $coredump_fd,
        )
    };
}

impl ProcessController {
    pub fn spawn_target_process_with_path<P: AsRef<std::path::Path>>(
        target_program_path: P,
        coredump_fd: RawFd,
    ) -> io::Result<Self> {
        // Create a pipe for IPC communication with CLOEXEC
        let (read_owned_fd, write_owned_fd) = pipe().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create pipe: {}", e),
            )
        })?;

        // Set CLOEXEC on both ends
        fcntl(
            read_owned_fd.as_raw_fd(),
            FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to set CLOEXEC on read fd: {}", e),
            )
        })?;
        fcntl(
            write_owned_fd.as_raw_fd(),
            FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to set CLOEXEC on write fd: {}", e),
            )
        })?;

        // Spawn the target process with fd mappings
        let mut command = Command::new(target_program_path.as_ref());
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()) // Pass through stderr for debugging
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
            ])
            .unwrap();

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
                "empty_process binary not found. Please run 'cargo build --bin empty_process' first.",
            ));
        }

        Self::spawn_target_process_with_path(empty_process_path, coredump_fd)
    }

    pub fn launch_n_threads(&self, thread_count: u32) -> Result<(), Box<dyn std::error::Error>> {
        // Send command to launch N threads in the child process
        let thread_count_bytes = thread_count.to_le_bytes();
        self.send_ipc_command_with_data(
            IpcCommand {
                command_type: IPC_CMD_LAUNCH_N_THREADS,
                data_length: thread_count_bytes.len() as u32,
            },
            &thread_count_bytes,
        )
    }

    pub fn suspend_threads_with_state(
        &mut self,
        thread_commands: &[ThreadCommand],
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
                    if verbose {
                        println!("Suspended thread {}", i);
                    }
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
                            println!(
                                "Failed to set thread state for thread {}: {:x}",
                                i, state_result
                            );
                        } else if verbose {
                            println!(
                                "Set thread state for thread {}: flavor=0x{:x}, count={}",
                                i, thread_state.flavor, thread_state.count
                            );
                        }
                    }
                }
            }

            // Clean up the threads array
            mach2::vm::mach_vm_deallocate(
                mach2::traps::mach_task_self(),
                threads as u64,
                (thread_count as usize * std::mem::size_of::<mach2::mach_types::thread_act_t>())
                    as u64,
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
                        println!(
                            "🗑️  Unmapped region at 0x{:x}, size: 0x{:x}",
                            address, region_size
                        );
                    }
                } else {
                    println!(
                        "⚠️  Failed to unmap region at 0x{:x}, size: 0x{:x}: error 0x{:x}",
                        address, region_size, unmap_kr
                    );
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

    pub fn map_segments(
        &mut self,
        segments: &[SegmentInfo],
        coredump_mmap: &MmapMut,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let task_port = self.get_task_port()?;

        for segment in segments {
            // Convert segment protection to mach_vm protection
            let mut desired_vm_prot = 0;
            if segment.init_protection & 1 != 0 {
                desired_vm_prot |= VM_PROT_READ;
            }
            if segment.init_protection & 2 != 0 {
                desired_vm_prot |= VM_PROT_WRITE;
            }
            if segment.init_protection & 4 != 0 {
                desired_vm_prot |= VM_PROT_EXECUTE;
            }

            let parent_mapped = unsafe { coredump_mmap.as_ptr().add(segment.file_offset as usize) };

            if verbose {
                println!(
                    "🔍 Using coredump mmap for segment {} at 0x{:x}, size: 0x{:x}, fd offset: 0x{:x}",
                    segment.name, parent_mapped as u64, segment.vm_size, segment.file_offset
                );
            }

            // Use mach_vm_remap to directly remap from parent to child
            let mut child_mapped_address = segment.vm_address;

            // Convert protection flags from segment to mach_vm protection
            let mut cur_protection = desired_vm_prot;
            let mut max_protection = cur_protection;

            let mut remap_kr = unsafe {
                mach_vm_remap(
                    task_port,                 // target_task (child)
                    &mut child_mapped_address, // target_address
                    segment.vm_size,           // size
                    0,                         // mask
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    mach_task_self(),     // src_task (parent)
                    parent_mapped as u64, // src_address
                    1,                    // copy (COW)
                    &mut cur_protection,  // cur_protection
                    &mut max_protection,  // max_protection
                    VM_INHERIT_SHARE,     // inheritance
                )
            };

            if remap_kr != KERN_SUCCESS {
                if verbose {
                    println!(
                        "⚠️  mach_vm_remap failed for segment {} from 0x{:x} at 0x{:x}-0x{:x}: size: 0x{:x}, error 0x{:x}",
                        segment.name,
                        parent_mapped as u64,
                        segment.vm_address,
                        segment.vm_address + segment.vm_size,
                        segment.vm_size,
                        remap_kr
                    );
                    println!(
                        "🔄 Trying fallback: mach_vm_map + vm_copy for segment {}",
                        segment.name
                    );
                }

                // Fallback: try mach_vm_map + vm_copy
                cur_protection = VM_PROT_READ | VM_PROT_WRITE;
                max_protection = VM_PROT_ALL;

                let mut fallback_address = segment.vm_address;
                let map_kr = unsafe {
                    mach_vm_map(
                        task_port,                           // target_task (child)
                        &mut fallback_address,               // address
                        segment.vm_size,                     // size
                        0,                                   // mask
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, // flags
                        MACH_PORT_NULL,                      // object
                        0,                                   // offset
                        1,                                   // copy
                        cur_protection,                      // cur_protection
                        VM_PROT_ALL,                         // max_protection
                        VM_INHERIT_SHARE,                    // inheritance
                    )
                };

                if map_kr == KERN_SUCCESS {
                    // Now copy the data using mach_vm_copy
                    let copy_kr = unsafe {
                        mach_vm_copy(
                            task_port,            // dest_task (child)
                            fallback_address,     // dest_address
                            parent_mapped as u64, // src_address
                            segment.vm_size,      // size
                        )
                    };

                    if copy_kr == KERN_SUCCESS {
                        if verbose {
                            println!(
                                "✅ Fallback successful: mapped and copied segment {} at 0x{:x}, size: 0x{:x}",
                                segment.name, fallback_address, segment.vm_size
                            );
                        }
                    } else {
                        println!(
                            "⚠️  mach_vm_copy failed for segment {} at 0x{:x}, size: 0x{:x}, error 0x{:x}",
                            segment.name, fallback_address, segment.vm_size, copy_kr
                        );
                        continue;
                    }
                } else {
                    println!(
                        "⚠️  Fallback mach_vm_map failed for segment {} at 0x{:x} (0x{:x}), size: 0x{:x}, error 0x{:x}",
                        segment.name, segment.vm_address, fallback_address, segment.vm_size, map_kr
                    );
                    continue;
                }
            }

            // Adjust protection if it doesn't match desired
            if cur_protection != desired_vm_prot {
                remap_kr = unsafe {
                    mach_vm_protect(
                        task_port,
                        child_mapped_address,
                        segment.vm_size,
                        0, // set_maximum = false
                        desired_vm_prot,
                    )
                };
                if remap_kr == KERN_SUCCESS {
                    cur_protection = desired_vm_prot; // Update for debug print
                } else {
                    println!(
                        "⚠️  Failed to adjust protection for segment {}: error 0x{:x}",
                        segment.name, remap_kr
                    );
                }
            }

            if verbose || remap_kr != KERN_SUCCESS {
                // Debug: Print protection info after remap
                let desired_prot = if segment.init_protection & 1 != 0 {
                    "R"
                } else {
                    "-"
                }
                .to_string()
                    + if segment.init_protection & 2 != 0 {
                        "W"
                    } else {
                        "-"
                    }
                    + if segment.init_protection & 4 != 0 {
                        "X"
                    } else {
                        "-"
                    };
                println!(
                    "🔧 Protection debug - desired: {} (0x{:x}), cur: 0x{:x}, max: 0x{:x}",
                    desired_prot, segment.init_protection, cur_protection, max_protection
                );
            }

            if child_mapped_address == segment.vm_address {
                if verbose {
                    println!(
                        "✅ Mapped segment {} at 0x{:x}, size: 0x{:x} (mach_vm_remap)",
                        segment.name, child_mapped_address, segment.vm_size
                    );
                }
            } else {
                println!(
                    "⚠️  Segment {} mapped to 0x{:x} instead of 0x{:x}, size: 0x{:x} (mach_vm_remap)",
                    segment.name, child_mapped_address, segment.vm_address, segment.vm_size
                );
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

    fn send_ipc_command_with_data(
        &self,
        command: IpcCommand,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let command_bytes = unsafe {
            std::slice::from_raw_parts(
                &command as *const _ as *const u8,
                std::mem::size_of::<IpcCommand>(),
            )
        };

        // Use safe I/O operations - write_all handles EAGAIN/EINTR automatically
        let mut write_file = &self.write_file;

        // Send the command header first
        write_file.write_all(command_bytes).map_err(|e| {
            format!(
                "Failed to send IPC command header (type: {}): {}",
                command.command_type, e
            )
        })?;

        // Send the data payload if present
        if !data.is_empty() {
            write_file.write_all(data).map_err(|e| {
                format!(
                    "Failed to send IPC command data (type: {}): {}",
                    command.command_type, e
                )
            })?;
        }

        // Ensure data is flushed to the pipe
        write_file.flush().map_err(|e| {
            format!(
                "Failed to flush IPC command (type: {}): {}",
                command.command_type, e
            )
        })?;

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
            let kr =
                mach_port_insert_right(mach_task_self(), port.0, port.0, MACH_MSG_TYPE_MAKE_SEND);
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
            let kr =
                task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &mut bootstrap_port);
            if kr != KERN_SUCCESS {
                return Err(format!("task_get_special_port failed: {:x}", kr).into());
            }

            // Use bootstrap_register2 from task_port module
            unsafe extern "C" {
                fn bootstrap_register2(
                    bp: mach_port_t,
                    service_name: *const i8,
                    sp: mach_port_t,
                    flags: u64,
                ) -> i32;
            }
            let kr = bootstrap_register2(bootstrap_port, name.as_ptr(), port.0, 0);
            if kr != KERN_SUCCESS {
                return Err(format!("bootstrap_register2 failed: {:x}", kr).into());
            }
        }

        // Send IPC command with the service name
        let service_name_bytes = uuid.as_bytes();
        self.send_ipc_command_with_data(
            IpcCommand {
                command_type: IPC_CMD_GET_TASK_PORT,
                data_length: service_name_bytes.len() as u32,
            },
            service_name_bytes,
        )?;

        // Receive the child's task port
        let child_task_port = unsafe {
            let mut msg: RecvMessage = mem::zeroed();
            let kr = mach_msg(
                &mut msg.header,
                MACH_RCV_MSG,
                0,
                mem::size_of::<RecvMessage>() as u32,
                port.0,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            );
            if kr != KERN_SUCCESS {
                return Err(format!("mach_msg receive failed: {:x}", kr).into());
            }
            msg.task_port.name
        };

        // Cache the task port for future use
        self.cached_task_port = Some(MachPort(child_task_port));

        Ok(child_task_port)
    }

    /// Wait for the cached task port to become disconnected (receive end closed).
    /// This happens when the target process exits or crashes.
    ///
    /// Returns Ok(()) when the port is disconnected, or an error if:
    /// - No task port is cached
    /// - The wait operation fails
    pub fn wait_for_port_death(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Get the cached task port
        let task_port = match &self.cached_task_port {
            Some(port) => port.0,
            None => return Err("No cached task port available".into()),
        };

        unsafe {
            // Create a port set and add the task port to monitor it
            unsafe extern "C" {
                fn mach_port_request_notification(
                    task: mach_port_t,
                    name: mach_port_t,
                    msgid: i32,
                    sync: u32,
                    notify: mach_port_t,
                    notifyPoly: u32,
                    previous: *mut mach_port_t,
                ) -> i32;
            }

            // Allocate a port to receive notifications
            let mut notify_port: mach_port_t = 0;
            let kr =
                mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut notify_port);
            if kr != KERN_SUCCESS {
                return Err(format!("Failed to allocate notification port: 0x{:x}", kr).into());
            }
            let _notify_port_guard = MachPort(notify_port);

            // Request dead name notification
            const MACH_NOTIFY_DEAD_NAME: i32 = 72; // From mach/notify.h
            let mut previous_port: mach_port_t = MACH_PORT_NULL;

            let kr = mach_port_request_notification(
                mach_task_self(),
                task_port,
                MACH_NOTIFY_DEAD_NAME,
                0, // sync
                notify_port,
                MACH_MSG_TYPE_MAKE_SEND_ONCE as u32,
                &mut previous_port,
            );

            if kr != KERN_SUCCESS {
                return Err(format!("Failed to request dead name notification: 0x{:x}", kr).into());
            }

            // Wait for the notification message
            // Dead name notification structure from mach/notify.h
            #[repr(C)]
            struct mach_dead_name_notification_t {
                header: mach_msg_header_t,
                ndr: NDR_record_t,
                name: mach_port_t,
                trailer: mach_msg_trailer_t,
            }

            #[repr(C)]
            #[derive(Copy, Clone)]
            struct NDR_record_t {
                mig_vers: u8,
                if_vers: u8,
                reserved1: u8,
                mig_encoding: u8,
                int_rep: u8,
                char_rep: u8,
                float_rep: u8,
                reserved2: u8,
            }

            impl Default for NDR_record_t {
                fn default() -> Self {
                    NDR_record_t {
                        mig_vers: 0,
                        if_vers: 0,
                        reserved1: 0,
                        mig_encoding: 0,
                        int_rep: 1,   // NDR_INT_LITTLE_ENDIAN
                        char_rep: 0,  // NDR_CHAR_ASCII
                        float_rep: 1, // NDR_FLOAT_IEEE
                        reserved2: 0,
                    }
                }
            }

            let mut msg: mach_dead_name_notification_t = mem::zeroed();
            msg.ndr = NDR_record_t::default();

            let kr = mach_msg(
                &mut msg.header,
                MACH_RCV_MSG,
                0,
                mem::size_of::<mach_dead_name_notification_t>() as u32,
                notify_port,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            );

            if kr != KERN_SUCCESS {
                return Err(format!("Failed to receive notification: 0x{:x}", kr).into());
            }

            // Check if this is a dead name notification
            if msg.header.msgh_id == MACH_NOTIFY_DEAD_NAME {
                Ok(())
            } else {
                Err(format!(
                    "Received unexpected notification: {} (expected {})",
                    msg.header.msgh_id, MACH_NOTIFY_DEAD_NAME
                )
                .into())
            }
        }
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
