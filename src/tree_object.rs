use anyhow::{Error, Result};

pub struct TreeNode<'a> {
    pub hash: String,
    pub path: &'a str,
    pub mode: &'a str,
}

pub fn parse_tree_object(buf: &[u8]) -> Result<Vec<TreeNode>> {
    let mut iter = buf.iter();

    let header_end_position = iter
        .position(|b| *b == b'\x00')
        .expect("null separator missed");

    let (object_type, _) = std::str::from_utf8(&buf[0..header_end_position])?
        .split_once(' ')
        .ok_or(Error::msg("Invalid node"))?;

    if object_type != "tree" {
        return Err(Error::msg("fatal: not a tree object"));
    }

    let mut nodes = vec![];
    let mut buf = &buf[header_end_position + 1..];

    while !buf.is_empty() {
        let (rest, node) = parse_node(buf)?;
        nodes.push(node);
        buf = rest;
    }

    Ok(nodes)
}

fn parse_node(buf: &[u8]) -> Result<(&[u8], TreeNode)> {
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
    Ok((&buf[hash_end..], TreeNode { path, hash, mode }))
}
