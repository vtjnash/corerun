use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_types::thread_act_t;
use mach2::mach_port::mach_port_deallocate;
use mach2::task::task_threads;
use mach2::thread_act::{thread_suspend, thread_set_state};
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_deallocate;
use mach2::bootstrap::bootstrap_look_up;
use mach2::task::{TASK_BOOTSTRAP_PORT, task_get_special_port};
use mach2::message::{
    MACH_MSGH_BITS, MACH_MSG_TYPE_COPY_SEND, MACH_MSGH_BITS_COMPLEX,
    mach_msg_send, mach_msg_header_t, mach_msg_body_t, mach_msg_port_descriptor_t
};
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use std::os::fd::{RawFd, FromRawFd};
use std::fs::File;
use std::io::Read;
use std::thread;
use std::ffi::CString;

#[derive(Debug)]
#[repr(C)]
struct IpcCommand {
    command_type: u32,
    data_length: u32,
}

/// The message format that the child sends to the parent.
#[repr(C)]
struct SendMessage {
    header: mach_msg_header_t,
    body: mach_msg_body_t,
    task_port: mach_msg_port_descriptor_t,
}

/// A wrapper for a `mach_port_t` to deallocate the port on drop.
struct MachPort(mach_port_t);

impl Drop for MachPort {
    fn drop(&mut self) {
        unsafe {
            mach_port_deallocate(mach_task_self(), self.0);
        }
    }
}

const IPC_CMD_UNMAP_ALL: u32 = 1;
const IPC_CMD_MAP_SEGMENT: u32 = 2;
const IPC_CMD_GET_TASK_PORT: u32 = 4;
const IPC_CMD_LAUNCH_N_THREADS: u32 = 5;

/// Send our task port to the parent via bootstrap server
fn send_task_port_to_parent(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let name = CString::new(service_name)?;
    
    unsafe {
        // Look up the registered port in bootstrap server
        let mut bootstrap_port: mach_port_t = std::mem::zeroed();
        let kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &mut bootstrap_port);
        if kr != KERN_SUCCESS {
            return Err(format!("task_get_special_port failed: {:x}", kr).into());
        }

        let mut parent_port: mach_port_t = std::mem::zeroed();
        let kr = bootstrap_look_up(bootstrap_port, name.as_ptr(), &mut parent_port);
        if kr != KERN_SUCCESS {
            return Err(format!("bootstrap_look_up failed: {:x}", kr).into());
        }
        let parent_port = MachPort(parent_port);
        
        let child_task = mach_task_self();
        
        // Send our task port to the parent
        let mut msg = SendMessage {
            header: mach_msg_header_t {
                msgh_bits: MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX,
                msgh_size: std::mem::size_of::<SendMessage>() as u32,
                msgh_remote_port: parent_port.0,
                msgh_local_port: child_task,
                msgh_voucher_port: MACH_PORT_NULL,
                msgh_id: 0,
            },
            body: mach_msg_body_t { msgh_descriptor_count: 1 },
            task_port: mach_msg_port_descriptor_t::new(child_task, MACH_MSG_TYPE_COPY_SEND),
        };
        
        let kr = mach_msg_send(&mut msg.header);
        if kr != KERN_SUCCESS {
            return Err(format!("mach_msg_send failed: {:x}", kr).into());
        }
    }
    
    Ok(())
}

fn handle_ipc_commands(ipc_fd: RawFd, coredump_fd: RawFd) {
    // Storage for created threads
    let mut created_threads: Vec<thread::JoinHandle<()>> = Vec::new();
    // Sleep for 1 second to give time to attach lldb
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    // Convert raw FD to File for safe I/O
    let mut ipc_file = unsafe { File::from_raw_fd(ipc_fd) };
    
    loop {
        let mut command_bytes = [0u8; std::mem::size_of::<IpcCommand>()];
        
        // Read the IPC command using safe I/O
        match ipc_file.read_exact(&mut command_bytes) {
            Ok(()) => {
                // Successfully read command
            },
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // Parent closed the pipe
                    return;
                } else {
                    eprintln!("Read error on IPC: {}", e);
                    return;
                }
            }
        }
        
        // Parse the command
        let command: IpcCommand = unsafe {
            std::ptr::read(command_bytes.as_ptr() as *const IpcCommand)
        };
        
        // Read command data if present
        let mut command_data = Vec::new();
        if command.data_length > 0 {
            command_data.resize(command.data_length as usize, 0);
            match ipc_file.read_exact(&mut command_data) {
                Ok(()) => {
                    // Successfully read command data
                },
                Err(e) => {
                    eprintln!("Failed to read command data: {}", e);
                    return;
                }
            }
        }

        // Handle the command
        match command.command_type {
            IPC_CMD_UNMAP_ALL => {
                unsafe {
                    // Unmap all memory using munmap
                    // Note: This is a simplified approach - in practice you'd want to
                    // iterate through /proc/self/maps or use platform-specific methods
                    // to unmap only the relevant segments
                    //libc::munmap(0 as *mut libc::c_void, usize::MAX);
                }
            },
            IPC_CMD_MAP_SEGMENT => {
                // Parse serialized segment data: address + size + file_offset + file_size + protection
                if command_data.len() >= 36 { // 8+8+8+8+4 bytes
                    let address = u64::from_le_bytes([
                        command_data[0], command_data[1], command_data[2], command_data[3],
                        command_data[4], command_data[5], command_data[6], command_data[7]
                    ]);
                    let size = u64::from_le_bytes([
                        command_data[8], command_data[9], command_data[10], command_data[11],
                        command_data[12], command_data[13], command_data[14], command_data[15]
                    ]);
                    let file_offset = u64::from_le_bytes([
                        command_data[16], command_data[17], command_data[18], command_data[19],
                        command_data[20], command_data[21], command_data[22], command_data[23]
                    ]);
                    let _file_size = u64::from_le_bytes([
                        command_data[24], command_data[25], command_data[26], command_data[27],
                        command_data[28], command_data[29], command_data[30], command_data[31]
                    ]);
                    let protection = u32::from_le_bytes([
                        command_data[32], command_data[33], command_data[34], command_data[35]
                    ]);

                    unsafe {
                        // Convert protection flags from Mach to mmap
                        let mut prot = 0;
                        if protection & 1 != 0 { prot |= libc::PROT_READ; }
                        if protection & 2 != 0 { prot |= libc::PROT_WRITE; }
                        if protection & 4 != 0 { prot |= libc::PROT_EXEC; }
                        
                        // Map the segment directly from the coredump file
                        let mapped_addr = libc::mmap(
                            address as *mut libc::c_void,
                            size as usize,
                            prot,
                            libc::MAP_PRIVATE | libc::MAP_FIXED,
                            coredump_fd,
                            file_offset as i64,
                        );
                        
                        if mapped_addr == libc::MAP_FAILED {
                            let error = std::io::Error::last_os_error();
                            eprintln!("Failed to map segment at 0x{:x}, size: 0x{:x}, offset: 0x{:x}: {} (errno: {})", 
                                    address, size, file_offset, error, error.raw_os_error().unwrap_or(-1));
                        }
                        else if mapped_addr != address as *mut libc::c_void {
                            eprintln!("Segment at 0x{:x} mapped to 0x{:x} instead, size: 0x{:x}, offset: 0x{:x}", 
                                    address, mapped_addr as usize, size, file_offset);
                        }
                        else {
                            eprintln!("Segment at 0x{:x} mapped successfully, size: 0x{:x}, offset: 0x{:x}", 
                                    address, size, file_offset);
                        }
                    }
                }
            },
            IPC_CMD_LAUNCH_N_THREADS => {
                // Launch N threads as requested
                if command.data_length >= 4 {
                    let thread_count = u32::from_le_bytes([
                        command_data[0], command_data[1], command_data[2], command_data[3]
                    ]);
                    
                    eprintln!("Launching {} threads", thread_count);
                    
                    // Create the requested number of threads
                    for thread_idx in 0..thread_count {
                        let handle = thread::spawn(move || {
                            // Block and do nothing - just exist to match thread count
                            loop {
                                thread::park();
                            }
                        });
                        created_threads.push(handle);
                        eprintln!("Created thread {}", thread_idx);
                    }
                } else {
                    eprintln!("Launch threads command received but no thread count provided");
                }
            },
            IPC_CMD_GET_TASK_PORT => {
                // Task port requested with service name in command_data
                if command.data_length > 0 {
                    let service_name = String::from_utf8_lossy(&command_data);
                    eprintln!("Task port requested for service: {}", service_name);
                    
                    // Close the IPC file and coredump file
                    drop(ipc_file);
                    unsafe { libc::close(coredump_fd); }
                    
                    // Send our task port to the parent via the provided service name
                    if let Err(e) = send_task_port_to_parent(&service_name) {
                        eprintln!("Failed to send task port to parent: {}", e);
                    }
                    
                    // Stop handling IPC commands after sending task port
                    return;
                } else {
                    eprintln!("Task port requested but no service name provided");
                }
            },
            _ => {
                // Unknown command, ignore
            }
        }
    }
}

fn main() {
    // Reset all signal handlers to default (DFL) to undo rust intervention breaking the ability to exit
    unsafe {
        for signal in 0..32 {
            libc::signal(signal, libc::SIG_DFL);
        }
    }

    // Check if we have the IPC pipe (fd 4) and coredump file (fd 3)
    let ipc_fd_exists = unsafe { libc::fcntl(4, libc::F_GETFD) != -1 };
    let coredump_fd_exists = unsafe { libc::fcntl(3, libc::F_GETFD) != -1 };
    
    if ipc_fd_exists && coredump_fd_exists {
        // Handle IPC commands in main thread
        handle_ipc_commands(4, 3);
    }

    // After IPC handling ends (when task port is sent), enter infinite loop
    loop {
        // Yield to avoid consuming too much CPU
        std::thread::yield_now();
    }
}