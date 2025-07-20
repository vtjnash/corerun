use crate::core_file_parser::SegmentInfo;
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::mach_port_deallocate;
use mach2::port::mach_port_t;
use mach2::vm::{mach_make_memory_entry_64, mach_vm_deallocate, mach_vm_map};
use mach2::vm_inherit::VM_INHERIT_COPY;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use std::os::fd::RawFd;
use std::ptr;

pub struct MemoryManager {
    task_port: mach_port_t,
    coredump_fd: RawFd,
}

impl MemoryManager {
    pub fn new(task_port: mach_port_t, coredump_fd: RawFd) -> Self {
        MemoryManager {
            task_port,
            coredump_fd,
        }
    }

    pub fn unmap_all_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let result = mach_vm_deallocate(
                self.task_port,
                0,
                mach_vm_size_t::MAX,
            );

            if result != KERN_SUCCESS {
                return Err(format!("Failed to deallocate memory: {}", result).into());
            }
        }

        Ok(())
    }

    pub fn map_segments(&self, segments: &[SegmentInfo]) -> Result<(), Box<dyn std::error::Error>> {
        for segment in segments {
            self.map_segment(segment)?;
        }
        Ok(())
    }

    fn map_segment(&self, segment: &SegmentInfo) -> Result<(), Box<dyn std::error::Error>> {
        if segment.file_size == 0 {
            return Ok(());
        }

        unsafe {
            // Step 1: mmap the file segment into our current process
            let file_mapping = libc::mmap(
                ptr::null_mut(),
                segment.file_size as libc::size_t,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                self.coredump_fd,
                segment.file_offset as libc::off_t,
            );

            if file_mapping == libc::MAP_FAILED {
                return Err(format!(
                    "Failed to mmap segment '{}' from file: {}",
                    segment.name, std::io::Error::last_os_error()
                ).into());
            }

            // Step 2: Create a memory entry from the mapped region
            let mut memory_entry: mach_port_t = 0;
            let mut entry_size = segment.file_size as mach_vm_size_t;
            
            let entry_result = mach_make_memory_entry_64(
                mach2::traps::mach_task_self(),
                &mut entry_size,
                file_mapping as mach_vm_address_t,
                VM_PROT_READ,
                &mut memory_entry,
                0, // parent_entry (none)
            );

            if entry_result != KERN_SUCCESS {
                libc::munmap(file_mapping, segment.file_size as libc::size_t);
                return Err(format!(
                    "Failed to create memory entry for segment '{}': {}",
                    segment.name, entry_result
                ).into());
            }

            // Step 3: Map the memory entry into the target process
            let mut target_address = segment.vm_address as mach_vm_address_t;
            let protection = self.convert_protection(segment.init_protection);
            let max_protection = self.convert_protection(segment.max_protection);

            let map_result = mach_vm_map(
                self.task_port,          // target task
                &mut target_address,     // address (in/out)
                segment.vm_size as mach_vm_size_t, // size
                0,                       // mask
                0,                       // flags (use exact address)
                memory_entry,            // object (memory entry)
                0,                       // offset in object
                0,                       // copy (0 = MAP_PRIVATE equivalent)
                protection,              // current protection
                max_protection,          // max protection
                VM_INHERIT_COPY,         // inheritance
            );

            // Clean up the memory entry port
            mach_port_deallocate(mach2::traps::mach_task_self(), memory_entry);

            // Clean up our mapping
            libc::munmap(file_mapping, segment.file_size as libc::size_t);

            if map_result != KERN_SUCCESS {
                return Err(format!(
                    "Failed to map segment '{}' into target process at address 0x{:x}: {}",
                    segment.name, segment.vm_address, map_result
                ).into());
            }

            if target_address != segment.vm_address as mach_vm_address_t {
                return Err(format!(
                    "Segment '{}' mapped at wrong address: expected 0x{:x}, got 0x{:x}",
                    segment.name, segment.vm_address, target_address
                ).into());
            }
        }

        Ok(())
    }

    fn convert_protection(&self, prot: u32) -> i32 {
        let mut vm_prot = 0;
        
        if prot & 0x1 != 0 {
            vm_prot |= VM_PROT_READ;
        }
        if prot & 0x2 != 0 {
            vm_prot |= VM_PROT_WRITE;
        }
        if prot & 0x4 != 0 {
            vm_prot |= VM_PROT_EXECUTE;
        }

        vm_prot
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_conversion() {
        let manager = MemoryManager::new(0, 0);
        
        // Test read-only
        assert_eq!(manager.convert_protection(0x1), VM_PROT_READ);
        
        // Test read-write
        assert_eq!(manager.convert_protection(0x3), VM_PROT_READ | VM_PROT_WRITE);
        
        // Test read-execute
        assert_eq!(manager.convert_protection(0x5), VM_PROT_READ | VM_PROT_EXECUTE);
        
        // Test read-write-execute
        assert_eq!(manager.convert_protection(0x7), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    }
}