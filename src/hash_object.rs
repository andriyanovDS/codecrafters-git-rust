use anyhow::{Error, Result};
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct ObjectHeader {
    pub object_type: ObjectType,
    pub length: u64,
}

impl ObjectHeader {
    pub fn new(object_type: ObjectType, length: u64) -> Self {
        Self {
            object_type,
            length,
        }
    }

    pub fn parse_bytes(buf: &[u8]) -> Result<(&[u8], ObjectHeader)> {
        let header_end_position = buf
            .iter()
            .position(|b| *b == 0)
            .expect("null separator missed");

        let (object_type, length) = std::str::from_utf8(&buf[0..header_end_position])?
            .split_once(' ')
            .ok_or(Error::msg("Invalid node"))?;

        let header = ObjectHeader {
            object_type: object_type.into(),
            length: length.parse()?,
        };
        Ok((&buf[header_end_position + 1..], header))
    }

    pub fn parse_str(buf: &str) -> Result<(&str, ObjectHeader)> {
        let header_end_position = buf
            .chars()
            .position(|b| b == '\x00')
            .expect("null separator missed");

        let (object_type, length) = buf[0..header_end_position]
            .split_once(' ')
            .ok_or(Error::msg("Invalid node"))?;

        let header = ObjectHeader {
            object_type: object_type.into(),
            length: length.parse()?,
        };
        Ok((&buf[header_end_position + 1..], header))
    }

    pub fn write<W: Write>(&self, buf: &mut W) -> Result<()> {
        self.object_type.write(buf)?;
        buf.write_all(&[b' '])?;
        buf.write_all(self.length.to_string().as_bytes())?;
        buf.write_all(&[0]).map_err(Error::from)
    }
}

#[derive(Debug, PartialEq)]
pub enum ObjectType {
    Blob,
    Tree,
    Commit,
}

impl ObjectType {
    fn write<W: Write>(&self, buf: &mut W) -> Result<()> {
        let str: &'static str = self.into();
        buf.write_all(str.as_bytes()).map_err(Error::from)
    }
}

impl Into<&'static str> for &ObjectType {
    fn into(self) -> &'static str {
        match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
            ObjectType::Commit => "commit",
        }
    }
}

impl<'a> From<&'a str> for ObjectType {
    fn from(value: &'a str) -> Self {
        match value {
            "blob" => ObjectType::Blob,
            "tree" => ObjectType::Tree,
            "commit" => ObjectType::Commit,
            _ => panic!("Unexpected object type {value:?}"),
        }
    }
}

pub struct Object {
    pub header: ObjectHeader,
    pub hash: String,
    pub content: Vec<u8>,
    pub root_dir: PathBuf,
}

impl Object {
    pub fn write(self) -> Result<String> {
        let file_path = make_object_path(self.hash.as_str(), self.root_dir)?;
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
        root_dir: ".".into(),
    };
    if write {
        object.write()
    } else {
        Ok(object.hash)
    }
}

pub fn make_object_path<P: AsRef<Path>>(hash: &str, root_dir: P) -> Result<PathBuf> {
    let objects_dir = root_dir.as_ref().join(".git/objects");
    let directory = objects_dir.join(&hash[0..2]);
    let file_path = directory.join(&hash[2..]);
    // println!("Write to dir: {file_path:?}");
    if !directory.exists() {
        std::fs::create_dir(directory)?;
    }
    Ok(file_path)
}
