use crate::hash_object::{Object, ObjectHeader, ObjectType};
use anyhow::{Error, Result};
use sha1::{Digest, Sha1};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const AUTHOR_NAME: &str = "test";
const AUTHOR_EMAIL: &str = "test@test.com";

#[derive(Debug)]
pub struct CommitAuthor {
    name: String,
    email: String,
    timestamp: String,
    timezone: String,
}

impl CommitAuthor {
    fn parse(buf: &str) -> Result<Self> {
        let mut parts = buf.split(' ');
        let name = parts.next().ok_or(Error::msg("Name missed."))?;
        let email = parts.next().ok_or(Error::msg("Email missed."))?;
        let timestamp = parts
            .next()
            .map(|str| &str[1..str.len() - 1])
            .ok_or(Error::msg("Timestamp missed."))?;
        let timezone = parts.next().ok_or(Error::msg("Timezone missed."))?;
        Ok(Self {
            name: name.to_string(),
            email: email.to_string(),
            timestamp: timestamp.to_string(),
            timezone: timezone.to_string(),
        })
    }

    fn write<W: Write>(&self, key: &str, buf: &mut W) -> Result<()> {
        buf.write_all(key.as_bytes())?;
        buf.write_all(&[b' '])?;
        buf.write_all(self.name.as_bytes())?;
        buf.write_all(&[b' ', b'<'])?;
        buf.write_all(self.email.as_bytes())?;
        buf.write_all(&[b'>', b' '])?;
        buf.write_all(self.timestamp.as_bytes())?;
        buf.write_all(&[b' '])?;
        buf.write_all(self.timezone.as_bytes()).map_err(Error::from)
    }
}

impl Default for CommitAuthor {
    fn default() -> Self {
        let unixtime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("expected system time")
            .as_secs();
        Self {
            name: AUTHOR_NAME.to_string(),
            email: AUTHOR_EMAIL.to_string(),
            timestamp: unixtime.to_string(),
            timezone: "+0000".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct CommitObject {
    pub tree_hash: String,
    pub parent_hashes: Vec<String>,
    pub author: CommitAuthor,
    pub commiter: CommitAuthor,
    pub message: String,
}

impl CommitObject {
    pub fn new(tree_hash: String, parent_hash: Option<String>, message: String) -> Self {
        Self {
            tree_hash,
            parent_hashes: parent_hash.map(|h| vec![h]).unwrap_or_default(),
            author: CommitAuthor::default(),
            commiter: CommitAuthor::default(),
            message,
        }
    }

    pub fn parse<P: AsRef<Path>>(hash: &str, target_dir: P) -> Result<Self> {
        let content = {
            let directory = &hash[0..2];
            let file_name = &hash[2..];
            let file_path = target_dir
                .as_ref()
                .join(".git/objects")
                .join(directory)
                .join(file_name);
            let file_content = std::fs::read(file_path)?;
            let mut decoder = flate2::read::ZlibDecoder::new(file_content.as_slice());
            let mut buffer = String::new();
            decoder.read_to_string(&mut buffer)?;
            buffer
        };

        let (file_content, header) = ObjectHeader::parse_str(&content)?;
        assert_eq!(header.object_type, ObjectType::Commit);

        let mut lines = file_content.lines();
        let tree_hash = lines
            .next()
            .expect("Tree hash must be first in commit object.")
            .split_once(' ')
            .expect("Tree hash must be separated by whitespace.")
            .1;
        let mut parent_hashes = Vec::<String>::new();
        let author = loop {
            let line = lines.next().ok_or(Error::msg("Author missed"))?;
            if line.starts_with("parent") {
                let (_, hash) = line.split_once(' ').ok_or(Error::msg("Incorrect parent"))?;
                parent_hashes.push(hash.to_string());
            } else {
                break CommitAuthor::parse(line);
            }
        }?;
        let commiter = lines
            .next()
            .map(CommitAuthor::parse)
            .ok_or(Error::msg("Committer missed"))??;

        let message = lines.nth(1).ok_or(Error::msg("Message missed"))?;
        Ok(Self {
            tree_hash: tree_hash.into(),
            parent_hashes,
            author,
            commiter,
            message: message.to_string(),
        })
    }

    pub fn write(&self) -> Result<String> {
        let mut content = Vec::<u8>::new();

        content.write_all("tree ".as_bytes())?;
        content.write_all(self.tree_hash.as_bytes())?;
        for parent_hash in self.parent_hashes.iter() {
            content.write_all(&[b'\n'])?;
            content.write_all("parent ".as_bytes())?;
            content.write_all(parent_hash.as_bytes())?;
        }
        content.write_all(&[b'\n'])?;
        self.author.write("author", &mut content)?;
        content.write_all(&[b'\n'])?;
        self.commiter.write("committer", &mut content)?;
        content.write_all(&[b'\n'])?;
        content.write_all(&[b'\n'])?;
        content.write_all(self.message.as_bytes())?;
        content.write_all(&[b'\n'])?;

        let header = ObjectHeader::new(ObjectType::Commit, content.len() as u64);
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
        object.write()
    }
}
