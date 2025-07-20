use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_types::thread_act_t;
use mach2::mach_port::mach_port_deallocate;
use mach2::task::task_threads;
use mach2::thread_act::{thread_suspend, thread_set_state};
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_deallocate;
use std::os::fd::{RawFd, FromRawFd};
use std::fs::File;
use std::io::Read;
use std::thread;

#[derive(Debug)]
#[repr(C)]
struct IpcCommand {
    command_type: u32,
    data_length: u32,
}

const IPC_CMD_UNMAP_ALL: u32 = 1;
const IPC_CMD_MAP_SEGMENT: u32 = 2;
const IPC_CMD_SUSPEND_THREADS: u32 = 3;

fn handle_ipc_commands(ipc_fd: RawFd, coredump_fd: RawFd) {
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
                        //if protection & 4 != 0 { prot |= libc::PROT_EXEC; }
                        
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
            IPC_CMD_SUSPEND_THREADS => {
                unsafe {
                    let task = mach_task_self();
                    let mut threads: *mut thread_act_t = std::ptr::null_mut();
                    let mut thread_count: u32 = 0;

                    // Parse serialized thread state data if present
                    let mut all_thread_states = Vec::new();
                    let mut max_thread_id = 0u32;
                    if !command_data.is_empty() {
                        // Parse serialized thread states from command_data
                        let mut offset = 0;
                        while offset + 16 <= command_data.len() { // 4 u32s minimum
                            let thread_id = u32::from_le_bytes([
                                command_data[offset], command_data[offset + 1],
                                command_data[offset + 2], command_data[offset + 3]
                            ]);
                            let flavor = u32::from_le_bytes([
                                command_data[offset + 4], command_data[offset + 5],
                                command_data[offset + 6], command_data[offset + 7]
                            ]);
                            let count = u32::from_le_bytes([
                                command_data[offset + 8], command_data[offset + 9],
                                command_data[offset + 10], command_data[offset + 11]
                            ]);
                            let data_size = u32::from_le_bytes([
                                command_data[offset + 12], command_data[offset + 13],
                                command_data[offset + 14], command_data[offset + 15]
                            ]);
                            
                            offset += 16;
                            
                            if offset + data_size as usize <= command_data.len() {
                                let state_data = &command_data[offset..offset + data_size as usize];
                                all_thread_states.push((thread_id, flavor, count, state_data));
                                max_thread_id = max_thread_id.max(thread_id);
                                offset += data_size as usize;
                            } else {
                                break;
                            }
                        }
                    }

                    // Create additional threads to match the expected thread count
                    // We need max_thread_id+1 total threads, and we already have 1 (this IPC thread)
                    let threads_to_create = if max_thread_id > 0 { max_thread_id } else { 0 };
                    let mut created_threads = Vec::new();
                    
                    for thread_idx in 0..threads_to_create {
                        let handle = std::thread::spawn(move || {
                            // Block and do nothing - just exist to match thread count
                            loop {
                                std::thread::park();
                            }
                        });
                        created_threads.push(handle);
                        eprintln!("Created thread {}", thread_idx);
                    }

                    // Get all threads in the task
                    let result = task_threads(task, &mut threads, &mut thread_count);
                    if result == KERN_SUCCESS {
                        // Suspend each thread except the current one (this IPC handler)
                        let current_thread = mach2::mach_init::mach_thread_self();
                        for i in 0..thread_count {
                            let thread = *threads.offset(i as isize);
                            if thread != current_thread {
                                thread_suspend(thread);
                                
                                // Set thread state from parsed data
                                for (state_idx, &(thread_id, flavor, count, state_data)) in all_thread_states.iter().enumerate() {
                                    if (thread_id == i) {
                                        let state_result = thread_set_state(
                                            thread,
                                            flavor as i32,
                                            state_data.as_ptr() as *mut u32,
                                            count,
                                        );
                                        if state_result != KERN_SUCCESS {
                                            eprintln!("Failed to set thread state {} (thread_id: {}) for thread {}: {}", state_idx, thread_id, i, state_result);
                                        } else {
                                            eprintln!("Set thread state {} (thread_id: {}) for thread {}: flavor=0x{:x}, count={}", 
                                                    state_idx, thread_id, i, flavor, count);
                                        }
                                    }
                                }
                            }
                        }

                        // Clean up the threads array with mach_vm_deallocate
                        mach_vm_deallocate(
                            task,
                            threads as u64,
                            (thread_count as usize * std::mem::size_of::<thread_act_t>()) as u64,
                        );
                        
                        // Deallocate the current_thread port
                        mach_port_deallocate(task, current_thread);
                    }
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
        // Spawn a thread to handle IPC commands
        thread::spawn(|| {
            handle_ipc_commands(4, 3);
        });
    }

    // Infinite loop - the parent process will send commands via IPC
    loop {
        // Yield to avoid consuming too much CPU
        std::thread::yield_now();
    }
}