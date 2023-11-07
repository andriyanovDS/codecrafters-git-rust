use std::{borrow::Cow, io::Write, os::unix::prelude::PermissionsExt, path::PathBuf};

use anyhow::{Error, Result};
use sha1::{Digest, Sha1};

use crate::hash_object::{hash_object, Object, ObjectHeader, ObjectType};

pub struct TreeNode<'a> {
    pub hash: String,
    pub path: String,
    pub mode: Cow<'a, str>,
}

impl<'a> TreeNode<'a> {
    fn parse(buf: &[u8]) -> Result<(&[u8], TreeNode)> {
        let separator_index = buf
            .iter()
            .position(|b| *b == 0)
            .ok_or(Error::msg("Invalid node"))?;
        let (mode, path) = std::str::from_utf8(&buf[0..separator_index])?
            .split_once(' ')
            .ok_or(Error::msg("Invalid node"))?;
        let hash_start = separator_index + 1;
        let hash_end = hash_start + 20;
        let hash = hex::encode(&buf[hash_start..hash_end]);
        Ok((
            &buf[hash_end..],
            TreeNode {
                path: path.to_string(),
                hash,
                mode: Cow::Borrowed(mode),
            },
        ))
    }

    fn write<W>(&self, dst: &mut W) -> Result<()>
    where
        W: Write,
    {
        dst.write_all(self.mode.as_bytes())?;
        dst.write_all(&[b' '])?;
        dst.write_all(self.path.as_bytes())?;
        dst.write_all(&[0])?;
        dst.write_all(&hex::decode(self.hash.as_str())?)
            .map_err(Error::from)
    }
}

pub fn write_tree(path: &PathBuf) -> Result<String> {
    let root_dir = std::fs::read_dir(path)?;
    let mut nodes = Vec::new();
    for entry in root_dir {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let mode: Cow<'static, str>;
        let hash = if path.is_dir() {
            if file_name == ".git" || file_name == "target" {
                continue;
            }
            mode = Cow::Borrowed("40000");
            write_tree(&path)?
        } else {
            let permissions = path.metadata()?.permissions();
            mode = Cow::Owned(format!("{:o}", permissions.mode()));
            hash_object(&path, false)?
        };
        nodes.push(TreeNode {
            mode,
            path: file_name,
            hash,
        });
    }
    nodes.sort_by_key(|n| n.path.clone());
    let mut content = Vec::new();
    for node in nodes {
        node.write(&mut content)?;
    }
    let header = ObjectHeader::new(ObjectType::Tree, content.len() as u64);
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
    object.write()
}

pub fn parse_tree_object(buf: &[u8]) -> Result<Vec<TreeNode>> {
    let (mut buf, header) = ObjectHeader::parse_bytes(buf)?;

    if header.object_type == ObjectType::Tree {
        return Err(Error::msg("fatal: not a tree object"));
    }

    let mut nodes = vec![];
    while !buf.is_empty() {
        let (rest, node) = TreeNode::parse(buf)?;
        nodes.push(node);
        buf = rest;
    }

    Ok(nodes)
}
