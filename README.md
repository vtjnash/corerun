# corerun

A Rust command line application for core operations.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
corerun [OPTIONS]
```

### Options

- `-i, --input <FILE>` - Sets the input file to use
- `-v, --verbose` - Turn on verbose output
- `-h, --help` - Print help information
- `-V, --version` - Print version information

### Examples

```bash
# Run with verbose output
corerun --verbose

# Run with input file
corerun --input myfile.txt

# Show help
corerun --help
```

## Development

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Documentation

Generate documentation:

```bash
cargo doc --open
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.