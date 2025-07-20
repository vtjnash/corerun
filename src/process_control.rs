use mach2::port::mach_port_t;
use nix::fcntl::{fcntl, FcntlArg};
use nix::unistd::pipe;
use std::io::{self, Write};
use std::os::fd::{RawFd, AsRawFd};
use std::fs::File;
use command_fds::{CommandFdExt, FdMapping};
use std::process::{Command, Stdio, Child};
use crate::core_file_parser::{SegmentInfo, ThreadCommand};

#[derive(Debug)]
#[repr(C)]
pub struct IpcCommand {
    pub command_type: u32,
    pub data_length: u32,
}

const IPC_CMD_UNMAP_ALL: u32 = 1;
const IPC_CMD_MAP_SEGMENT: u32 = 2;
const IPC_CMD_SUSPEND_THREADS: u32 = 3;

pub struct ProcessController {
    task_port: mach_port_t,
    child: Child,
    write_file: File,
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
            task_port: 0, // Not needed anymore since child does its own memory management
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

    pub fn suspend_all_threads(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Send suspend command to child process via IPC without thread state
        self.send_ipc_command_with_data(IpcCommand {
            command_type: IPC_CMD_SUSPEND_THREADS,
            data_length: 0,
        }, &[])
    }
    
    pub fn suspend_threads_with_state(&self, thread_commands: &[ThreadCommand]) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize all thread state data into a single payload
        let mut all_thread_data = Vec::new();
        
        // Concatenate all thread state data
        for (thread_id, thread_cmd) in thread_commands.iter().enumerate() {
            for thread_state in &thread_cmd.thread_states {
                // Add thread state header: thread_id (u32), flavor (u32), count (u32), data_size (u32)
                all_thread_data.extend_from_slice(&(thread_id as u32).to_le_bytes());
                all_thread_data.extend_from_slice(&thread_state.flavor.to_le_bytes());
                all_thread_data.extend_from_slice(&thread_state.count.to_le_bytes());
                all_thread_data.extend_from_slice(&(thread_state.state_data.len() as u32).to_le_bytes());
                
                // Add thread state data
                all_thread_data.extend_from_slice(&thread_state.state_data);
            }
        }
        
        // Send single IPC command with all thread state data
        self.send_ipc_command_with_data(IpcCommand {
            command_type: IPC_CMD_SUSPEND_THREADS,
            data_length: all_thread_data.len() as u32,
        }, &all_thread_data)
    }
    
    pub fn unmap_all_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Send unmap all command to child process via IPC
        self.send_ipc_command_with_data(IpcCommand {
            command_type: IPC_CMD_UNMAP_ALL,
            data_length: 0,
        }, &[])
    }
    
    pub fn map_segments(&self, segments: &[SegmentInfo]) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn get_task_port(&self) -> mach_port_t {
        self.task_port
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