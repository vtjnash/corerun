# corerun

A Rust command line application for core dump analysis and process memory recreation using advanced memory mapping techniques.

## Overview

corerun is a sophisticated tool for reconstructing process memory from core dump files. It parses both MachO and ELF core dump formats, recreates the original process memory layout using `mach_vm_remap` for efficient copy-on-write mapping, and restores thread states to enable debugging of crashed processes.

## Features (generated by Claude AI)

- **Multi-format Support**: Handles both MachO and ELF core dump formats
- **Advanced Memory Mapping**: Uses `mach_vm_remap` with copy-on-write for efficient memory recreation
- **Thread State Restoration**: Recreates threads with original CPU register states and exception information
- **Automatic Conflict Resolution**: Intelligently handles memory address conflicts with retry logic
- **Bootstrap IPC**: Clean inter-process communication using Mach bootstrap services
- **Protection Handling**: Preserves original memory protection flags (read/write/execute)

## Requirements

- Currently supported on macOS only (tested on macOS 14+)
- Rust 1.70+
- The target process needs the `com.apple.security.get-task-allow` entitlement for core dump generation (automatically granted for debug builds)

## Installation

```bash
git clone https://github.com/your-username/corerun.git
cd corerun
cargo build --release
```

## Usage

### Basic Usage

```bash
./target/release/corerun /path/to/core.dump
```

### Verbose Mode

For detailed information about the parsing and mapping process:

```bash
./target/release/corerun -v /path/to/core.dump
```

## Example Output

```
Verbose mode enabled
Using coredump file: /cores/core.46688
Parsing core dump file...
Core dump file type: "Core"
Entry point: 0x0
Found 219 segments:
   - addr: 0x102d1c000, size: 0x4000, offset: 0x8000, prot: max=0x5 init=0x5
   - addr: 0x102d20000, size: 0x4000, offset: 0xc000, prot: max=0x3 init=0x1
   - addr: 0x102d24000, size: 0x4000, offset: 0x10000, prot: max=0x3 init=0x3
   - addr: 0x102d28000, size: 0x8000, offset: 0x14000, prot: max=0x1 init=0x1
   - addr: 0x102d30000, size: 0x8000, offset: 0x1c000, prot: max=0x7 init=0x3
   - addr: 0x102d38000, size: 0x8000, offset: 0x24000, prot: max=0x1 init=0x1
   - addr: 0x102d40000, size: 0x4000, offset: 0x2c000, prot: max=0x7 init=0x1
   - addr: 0x102d44000, size: 0x4000, offset: 0x30000, prot: max=0x7 init=0x3
   - addr: 0x102d48000, size: 0x4000, offset: 0x34000, prot: max=0x7 init=0x0
   - addr: 0x102d4c000, size: 0x8000, offset: 0x38000, prot: max=0x7 init=0x3
   ...

Found 13 thread commands:
  Thread command 0: 2 thread states
  State 0:
    State: flavor=0x6 (ARM_THREAD_STATE64), count=68, data_len=272
      Data: 00000000 00000000 17c67170 00000001 119ff6f8 00000001 119fee44 00000001
            00000000 00000000 00000000 00000000 00000001 00000000 00000000 00000000
            ...
  State 1:
    State: flavor=0x7 (ARM_EXCEPTION_STATE64), count=4, data_len=16
      Data: 00000000 00000000 92000006 00000000

Spawning target process...
Launching 13 threads in target process...
Retrieving task port...
Target process spawned with PID: 52643
Target process task_port: 7171
✅ Task port verification successful: pid_for_task(7171) == 52643

Suspending target process threads...
Suspended thread 0
Set thread state for thread 0: flavor=0x6, count=68
Set thread state for thread 0: flavor=0x7, count=4
...

Unmapping existing process memory...
🗑️  Unmapped region at 0x100d0c000, size: 0x50000
🗑️  Unmapped region at 0x100d5c000, size: 0x4000
...
✅ Unmapped 99 memory regions total

Mapping segments from coredump...
🔍 Parent mapped segment  at 0x104b40000, size: 0x4000, fd offset: 0x8000
🔧 Protection debug - desired: R-X (0x5), cur: 0x5, max: 0x7
✅ Mapped segment  at 0x102d1c000, size: 0x4000 (mach_vm_remap)
...

Successfully recreated process memory from coredump!
Target process PID: 52643
Process is suspended - you can now attach a debugger or analyze it
Waiting for target process to exit...
```

## Architecture

corerun uses a sophisticated multi-process architecture:

1. **Parent Process**: Parses the core dump, manages memory mapping, and coordinates the recreation
2. **Target Process**: Empty process that receives memory segments and thread states
3. **Bootstrap IPC**: Secure communication channel for task port exchange
4. **Memory Mapping**: Efficient COW mapping using `mach_vm_remap` from parent to child

### Key Components

- **Core File Parser**: Handles both MachO and ELF formats with proper segment and thread state parsing
- **Process Controller**: Manages the target process lifecycle and IPC communication
- **Memory Manager**: Advanced memory mapping with conflict resolution and protection handling
- **Task Port Exchange**: Secure bootstrap-based IPC for task port acquisition

## Protection Flags

Protection flags are displayed in verbose mode:
- `R--`: Read-only (0x1)
- `-W-`: Write-only (0x2)
- `--X`: Execute-only (0x4)
- `RW-`: Read+Write (0x3)
- `R-X`: Read+Execute (0x5)
- `RWX`: Read+Write+Execute (0x7)
- `---`: No access (0x0)

## Debugging

After corerun recreates the process memory, you can attach a debugger:

```bash
lldb -p <target_process_pid>
```

The process will be suspended with all original thread states and memory layout restored.

## Development

### Building

```bash
cargo build --bin empty_process  # Build the target process binary
cargo build                      # Build the main corerun binary
```

### Testing

```bash
cargo test
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
