use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{fs, io::Read};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
#[clap(rename_all = "kebab-case")]
enum Command {
    Init,
    CatFile {
        #[clap(short)]
        print: bool,
        hash: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => {
            fs::create_dir(".git")?;
            fs::create_dir(".git/objects")?;
            fs::create_dir(".git/refs")?;
            fs::write(".git/HEAD", "ref: refs/heads/master\n")?;
            println!("Initialized git directory")
        }
        Command::CatFile { print: _, hash } => {
            let directory = &hash[0..2];
            let file_name = &hash[2..];
            let file_path = format!(".git/objects/{}/{}", directory, file_name);
            let file_content = fs::read(&file_path)?;
            let mut decoder = flate2::read::ZlibDecoder::new(file_content.as_slice());
            let mut result = String::new();
            decoder.read_to_string(&mut result)?;
            print!("{}", result);
        }
    }
    Ok(())
}
