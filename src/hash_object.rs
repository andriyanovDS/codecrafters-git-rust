use anyhow::{Error, Result};
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct ObjectHeader {
    object_type: ObjectType,
    length: u64,
}

impl ObjectHeader {
    pub fn new(object_type: ObjectType, length: u64) -> Self {
        Self {
            object_type,
            length,
        }
    }
    pub fn write<W: Write>(&self, buf: &mut W) -> Result<()> {
        self.object_type.write(buf)?;
        buf.write_all(&[b' '])?;
        buf.write_all(self.length.to_string().as_bytes())?;
        buf.write_all(&[0]).map_err(Error::from)
    }
}

pub enum ObjectType {
    Blob,
    Tree,
}

impl ObjectType {
    fn write<W: Write>(&self, buf: &mut W) -> Result<()> {
        let str = match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
        };
        buf.write_all(str.as_bytes()).map_err(Error::from)
    }
}

pub struct Object {
    pub header: ObjectHeader,
    pub hash: String,
    pub content: Vec<u8>,
}

impl Object {
    pub fn write(self) -> Result<String> {
        let file_path = make_object_path(self.hash.as_str())?;
        let file = std::fs::File::create(file_path)?;
        let mut encoder = flate2::write::ZlibEncoder::new(file, Compression::none());
        self.header.write(&mut encoder)?;
        encoder.write_all(&self.content)?;
        encoder.finish()?;
        Ok(self.hash)
    }
}

pub fn hash_object(file_path: &PathBuf, write: bool) -> Result<String> {
    let file = std::fs::File::open(file_path)?;
    let file_len = file.metadata()?;
    let mut content = Vec::<u8>::new();
    let header = ObjectHeader {
        object_type: ObjectType::Blob,
        length: file_len.len(),
    };
    let mut buf_reader = std::io::BufReader::new(file);
    buf_reader.read_to_end(&mut content)?;
    let hash = {
        let mut hasher = Sha1::new();
        header.write(&mut hasher)?;
        hasher.update(&content);
        hex::encode(hasher.finalize())
    };
    let object = Object {
        header,
        hash,
        content,
    };
    if write {
        object.write()
    } else {
        Ok(object.hash)
    }
}

pub fn make_object_path(hash: &str) -> Result<String> {
    let directory = format!(".git/objects/{}", &hash[0..2]);
    let file_path = format!("{}/{}", directory, &hash[2..]);
    let directory_path = Path::new(directory.as_str());
    if !directory_path.exists() {
        std::fs::create_dir(directory_path)?;
    }
    Ok(file_path)
}
