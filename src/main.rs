use anyhow::Result;
use clap::{Parser, Subcommand};
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tree_object::parse_tree_object;

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
            let file = std::fs::File::open(file_path)?;
            let file_len = file.metadata()?;
            let mut object_file = Vec::<u8>::new();
            object_file.extend("blob".as_bytes());
            object_file.push(b' ');
            object_file.extend(file_len.len().to_string().as_bytes());
            object_file.push(b'\x00');
            let mut buf_reader = std::io::BufReader::new(file);
            buf_reader.read_to_end(&mut object_file)?;

            let mut hasher = Sha1::new();
            hasher.update(&object_file);
            let hash = hex::encode(hasher.finalize());
            if write {
                let directory = format!(".git/objects/{}", &hash[0..2]);
                let file_path = format!("{}/{}", directory, &hash[2..]);
                let directory_path = Path::new(directory.as_str());
                if !directory_path.exists() {
                    std::fs::create_dir(directory_path)?;
                }
                let file = std::fs::File::create(file_path)?;
                let mut encoder = flate2::write::ZlibEncoder::new(file, Compression::none());
                encoder.write_all(&object_file)?;
                encoder.finish()?;
            }
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
    }
    Ok(())
}
