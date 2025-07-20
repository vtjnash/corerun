use object::{Object, ObjectSegment, SegmentFlags};
use object::read::macho::LoadCommandVariant;
use object::read::elf::ProgramHeader;
use object::elf::{NT_PRSTATUS, NT_FPREGSET};

// ARM thread state constants
const ARM_THREAD_STATE64: u32 = 6;
const ARM_EXCEPTION_STATE64: u32 = 7;

#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub max_protection: u32,
    pub init_protection: u32,
}

#[derive(Debug, Clone)]
pub struct ThreadState {
    pub flavor: u32,
    pub count: u32,
    pub state_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ThreadCommand {
    pub thread_states: Vec<ThreadState>,
}

pub struct CoreFileParser<'data> {
    object: object::File<'data>,
}

impl<'data> CoreFileParser<'data> {
    pub fn new(data: &'data [u8]) -> Result<CoreFileParser<'data>, Box<dyn std::error::Error>> {
        let object = object::File::parse(data)?;
        Ok(CoreFileParser { object })
    }
    

    pub fn parse_segments(&self) -> Result<Vec<SegmentInfo>, Box<dyn std::error::Error>> {
        let mut segments = Vec::new();

        for segment in self.object.segments() {
            let name = segment.name()?.unwrap_or("<unknown>").to_string();
            let (file_offset, file_size) = segment.file_range();
            
            // Get protection flags from segment flags
            let (max_protection, init_protection) = self.extract_protection_from_segment(&segment);
            
            let segment_info = SegmentInfo {
                name,
                vm_address: segment.address(),
                vm_size: segment.size(),
                file_offset,
                file_size,
                max_protection,
                init_protection,
            };
            
            segments.push(segment_info);
        }

        Ok(segments)
    }

    pub fn get_entry_point(&self) -> u64 {
        self.object.entry()
    }
    
    pub fn get_kind(&self) -> String {
        format!("{:?}", self.object.kind())
    }


    pub fn parse_thread_states(&self) -> Result<Vec<ThreadCommand>, Box<dyn std::error::Error>> {
        let mut thread_commands = Vec::new();
        
        match &self.object {
            object::File::MachO64(macho_file) => {
                // Use load command variants to find thread commands
                for load_command_result in macho_file.macho_load_commands()? {
                    let load_command_data = load_command_result?;
                    
                    // Check if this is a thread command using variant()
                    if let Ok(LoadCommandVariant::Thread(_thread_command, thread_data)) = load_command_data.variant() {
                        // Parse thread states from the raw thread data
                        let thread_states = self.parse_thread_states_from_data(thread_data)?;
                        thread_commands.push(ThreadCommand { thread_states });
                    }
                }
            },
            object::File::MachO32(macho_file) => {
                // Handle MachO32 - similar structure
                for load_command_result in macho_file.macho_load_commands()? {
                    let load_command_data = load_command_result?;
                    
                    if let Ok(LoadCommandVariant::Thread(_thread_command, thread_data)) = load_command_data.variant() {
                        // Parse thread states from the raw thread data
                        let thread_states = self.parse_thread_states_from_data(thread_data)?;
                        thread_commands.push(ThreadCommand { thread_states });
                    }
                }
            },
            object::File::Elf32(elf_file) => {
                // Parse ELF PT_NOTE segments for thread states  
                for header in elf_file.elf_program_headers() {
                    if let Ok(Some(mut notes)) = header.notes(elf_file.endian(), elf_file.data()) {
                        while let Some(note) = notes.next()? {
                            if note.name() == b"CORE" {
                                match note.n_type(elf_file.endian()) {
                                    NT_PRSTATUS => { // General purpose registers
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: NT_PRSTATUS,
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            thread_commands.push(ThreadCommand {
                                                thread_states: vec![thread_state],
                                            });
                                        }
                                    },
                                    NT_FPREGSET => { // Floating point registers
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: NT_FPREGSET,
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            if let Some(last_cmd) = thread_commands.last_mut() {
                                                last_cmd.thread_states.push(thread_state);
                                            } else {
                                                thread_commands.push(ThreadCommand {
                                                    thread_states: vec![thread_state],
                                                });
                                            }
                                        }
                                    },
                                    _ => {
                                        // Other CORE note types
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: note.n_type(elf_file.endian()),
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            if let Some(last_cmd) = thread_commands.last_mut() {
                                                last_cmd.thread_states.push(thread_state);
                                            } else {
                                                thread_commands.push(ThreadCommand {
                                                    thread_states: vec![thread_state],
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            object::File::Elf64(elf_file) => {
                // Parse ELF PT_NOTE segments for thread states  
                for header in elf_file.elf_program_headers() {
                    if let Ok(Some(mut notes)) = header.notes(elf_file.endian(), elf_file.data()) {
                        while let Some(note) = notes.next()? {
                            if note.name() == b"CORE" {
                                match note.n_type(elf_file.endian()) {
                                    NT_PRSTATUS => { // General purpose registers
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: NT_PRSTATUS,
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            thread_commands.push(ThreadCommand {
                                                thread_states: vec![thread_state],
                                            });
                                        }
                                    },
                                    NT_FPREGSET => { // Floating point registers
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: NT_FPREGSET,
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            if let Some(last_cmd) = thread_commands.last_mut() {
                                                last_cmd.thread_states.push(thread_state);
                                            } else {
                                                thread_commands.push(ThreadCommand {
                                                    thread_states: vec![thread_state],
                                                });
                                            }
                                        }
                                    },
                                    _ => {
                                        // Other CORE note types
                                        let desc = note.desc();
                                        if desc.len() >= 4 {
                                            let thread_state = ThreadState {
                                                flavor: note.n_type(elf_file.endian()),
                                                count: (desc.len() / 4) as u32,
                                                state_data: desc.to_vec(),
                                            };
                                            
                                            if let Some(last_cmd) = thread_commands.last_mut() {
                                                last_cmd.thread_states.push(thread_state);
                                            } else {
                                                thread_commands.push(ThreadCommand {
                                                    thread_states: vec![thread_state],
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            _ => {
                // Unsupported file format for thread states
            }
        }
        
        Ok(thread_commands)
    }
    
    fn parse_thread_states_from_data(&self, data: &[u8]) -> Result<Vec<ThreadState>, Box<dyn std::error::Error>> {
        let mut thread_states = Vec::new();
        let mut offset = 0;
        
        // Parse thread states from the raw command data
        while offset + 8 <= data.len() {
            // Each thread state has: flavor (u32), count (u32), then data
            let flavor = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            let count = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            
            offset += 8;
            
            // Read the state data (count * 4 bytes)
            let state_data_size = (count * 4) as usize;
            if offset + state_data_size <= data.len() {
                let state_data = data[offset..offset + state_data_size].to_vec();
                offset += state_data_size;
                
                thread_states.push(ThreadState {
                    flavor,
                    count,
                    state_data,
                });
            } else {
                break; // Not enough data for this state
            }
        }
        
        Ok(thread_states)
    }


    pub fn format_thread_state_verbose(&self, thread_state: &ThreadState) -> String {
        let mut output = String::new();
        
        // Detect ARM thread state types
        let state_type = match thread_state.flavor {
            ARM_THREAD_STATE64 => " (ARM_THREAD_STATE64)",
            ARM_EXCEPTION_STATE64 => " (ARM_EXCEPTION_STATE64)",
            _ => "",
        };
        
        output.push_str(&format!("    State: flavor=0x{:x}{}, count={}, data_len={}\n", 
                                thread_state.flavor, state_type, thread_state.count, thread_state.state_data.len()));
        
        // Print data in hex blocks of 4 bytes
        output.push_str("      Data: ");
        for (i, chunk) in thread_state.state_data.chunks(4).enumerate() {
            if i > 0 && i % 8 == 0 {
                output.push_str("\n            ");
            }
            
            // Pad chunk to 4 bytes if needed
            let mut padded_chunk = [0u8; 4];
            for (j, &byte) in chunk.iter().enumerate() {
                if j < 4 {
                    padded_chunk[j] = byte;
                }
            }
            
            // Convert to u32 and print as hex
            let value = u32::from_le_bytes(padded_chunk);
            output.push_str(&format!("{:08x} ", value));
        }
        output.push('\n');
        
        output
    }

    fn extract_protection_from_segment(&self, segment: &object::Segment) -> (u32, u32) {
        // Extract protection from segment flags for any format
        let segment_flags = segment.flags();
        
        match segment_flags {
            SegmentFlags::MachO { maxprot, initprot, .. } => {
                (maxprot, initprot)
            },
            SegmentFlags::Elf { p_flags } => {
                // ELF segment flags: PF_X = 1, PF_W = 2, PF_R = 4
                // Convert to Mach-O style: PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4
                let mut protection = 0u32;
                if p_flags & 4 != 0 { protection |= 1; } // PF_R -> PROT_READ
                if p_flags & 2 != 0 { protection |= 2; } // PF_W -> PROT_WRITE
                if p_flags & 1 != 0 { protection |= 4; } // PF_X -> PROT_EXEC
                
                // For ELF, max and init protection are typically the same
                (protection, protection)
            },
            SegmentFlags::Coff { characteristics } => {
                // COFF/PE segment characteristics to protection mapping
                let mut protection = 0u32;
                // IMAGE_SCN_MEM_READ = 0x40000000, IMAGE_SCN_MEM_WRITE = 0x80000000, IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if characteristics & 0x40000000 != 0 { protection |= 1; } // Read
                if characteristics & 0x80000000 != 0 { protection |= 2; } // Write  
                if characteristics & 0x20000000 != 0 { protection |= 4; } // Execute
                
                (protection, protection)
            },
            SegmentFlags::None => {
                // Default RWX for unknown formats
                (0x7, 0x7)
            },
            _ => {
                // Catch-all for any other variants
                (0x7, 0x7)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_info_creation() {
        let segment = SegmentInfo {
            name: "TEXT".to_string(),
            vm_address: 0x1000,
            vm_size: 0x2000,
            file_offset: 0,
            file_size: 0x2000,
            max_protection: 0x7,
            init_protection: 0x5,
        };

        assert_eq!(segment.name, "TEXT");
        assert_eq!(segment.vm_address, 0x1000);
        assert_eq!(segment.vm_size, 0x2000);
    }
}