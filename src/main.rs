use clap::{Arg, Command};

/// Main entry point for the corerun application.
/// 
/// This function sets up command line argument parsing using clap and processes
/// the provided arguments to configure the application behavior.
fn main() {
    let matches = Command::new("corerun")
        .author("Jameson Nash <vtjnash@gmail.com>")
        .version("0.1.0")
        .about("A Rust command line application")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Sets the input file to use")
                .required(false),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Turn on verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    if matches.get_flag("verbose") {
        println!("Verbose mode enabled");
    }

    if let Some(input_file) = matches.get_one::<String>("input") {
        println!("Using input file: {}", input_file);
    }

    println!("corerun is running!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_app_creation() {
        let app = Command::new("corerun")
            .author("Jameson Nash <vtjnash@gmail.com>")
            .version("0.1.0")
            .about("A Rust command line application");
        
        assert_eq!(app.get_name(), "corerun");

    }
