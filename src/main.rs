use anyhow::Result;
use clap::{Parser, Subcommand};
use clone::clone;
use commit_object::CommitObject;
use repo::init_repo;
use std::path::PathBuf;
use tree_object::{write_tree, TreeNode};

use crate::hash_object::{hash_object, read_object, ObjectHeader};

mod clone;
mod commit_object;
mod hash_object;
mod repo;
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
    Clone {
        repo_url: String,
        detination_path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => {
            init_repo(".")?;
            println!("Initialized git directory")
        }
        Command::CatFile { print: _, hash } => {
            let object = read_object(hash.as_str(), ".")?;
            let (content, _) = ObjectHeader::parse_bytes(object.as_slice())?;
            print!("{}", String::from_utf8_lossy(content));
        }
        Command::HashObject { write, file_path } => {
            let hash = hash_object(&file_path, write)?;
            println!("{hash}");
        }
        Command::LsTree { name_only, hash } => {
            let nodes = TreeNode::read(hash.as_str(), ".")?;
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
        Command::Clone {
            repo_url,
            detination_path,
        } => clone(repo_url, detination_path)?,
    }
    Ok(())
}
