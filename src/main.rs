use anyhow::Result;
use clap::{Parser, Subcommand};
use commit_object::CommitObject;
use std::{fs, io::Read, path::PathBuf};
use tree_object::{parse_tree_object, write_tree};

use crate::hash_object::hash_object;

mod commit_object;
mod hash_object;
mod tree_object;

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
    HashObject {
        #[clap(short)]
        write: bool,
        file_path: PathBuf,
    },
    LsTree {
        #[arg(long("name-only"))]
        name_only: bool,
        hash: String,
    },
    WriteTree,
    CommitTree {
        tree_hash: String,
        #[clap(short)]
        parent_hash: Option<String>,
        #[clap(short)]
        message: String,
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
            let file_content = fs::read(file_path)?;
            let mut decoder = flate2::read::ZlibDecoder::new(file_content.as_slice());

            let mut result = String::new();
            decoder.read_to_string(&mut result)?;
            let contect_start_index = result
                .chars()
                .position(|c| c as u8 == 0x0)
                .expect("null separator missed");
            print!("{}", &result[contect_start_index + 1..]);
        }
        Command::HashObject { write, file_path } => {
            let hash = hash_object(&file_path, write)?;
            println!("{hash}");
        }
        Command::LsTree { name_only, hash } => {
            let directory = &hash[0..2];
            let file_name = &hash[2..];
            let file_path = format!(".git/objects/{}/{}", directory, file_name);
            let file_content = fs::read(&file_path)?;
            let mut decoder = flate2::read::ZlibDecoder::new(file_content.as_slice());

            let mut buffer = Vec::new();
            decoder.read_to_end(&mut buffer)?;

            let nodes = parse_tree_object(buffer.as_slice())?;
            for node in nodes {
                if name_only {
                    println!("{}", node.path);
                } else {
                    println!("{} {} {}", node.mode, node.hash, node.path);
                }
            }
        }
        Command::WriteTree => {
            let hash = write_tree(&std::env::current_dir()?)?;
            println!("{hash}");
        }
        Command::CommitTree {
            tree_hash,
            parent_hash,
            message,
        } => {
            let commit_hash = CommitObject::new(tree_hash, parent_hash, message).write()?;
            println!("{commit_hash}");
        }
    }
    Ok(())
}
