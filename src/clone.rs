use anyhow::{Error, Result};
use bytes::Bytes;
use flate2::bufread::ZlibDecoder;
use reqwest::blocking::{Client, Response};
use reqwest::{header::CONTENT_TYPE, Url};
use sha1::{Digest, Sha1};
use std::io::BufRead;
use std::{
    borrow::Cow,
    collections::HashSet,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::commit_object::CommitObject;
use crate::tree_object::TreeNode;
use crate::{
    hash_object::{Object, ObjectHeader, ObjectType},
    repo::init_repo,
};

const GIT_UPLOAD_PACK_CONTENT_TYPE: &str = "application/x-git-upload-pack-advertisement";

#[derive(Debug)]
struct LsRefsResponse {
    refs: Vec<Ref>,
    capabilities: HashSet<String>,
}

impl TryFrom<Vec<Message>> for LsRefsResponse {
    type Error = Error;
    fn try_from(value: Vec<Message>) -> Result<Self> {
        let mut iter = value.into_iter();
        let first_message = iter
            .next()
            .ok_or(Error::msg("Must be at least two messages"))?
            .0;
        assert_eq!(first_message.len(), 1);
        assert_eq!(first_message[0], &"# service=git-upload-pack\n");

        let second_message = iter
            .next()
            .ok_or(Error::msg("Must be at least two messages"))?
            .0;
        let mut refs_iter = second_message.into_iter();
        let Some(first_ref) = refs_iter.next() else {
            return Ok(Self {
                refs: vec![],
                capabilities: Default::default(),
            });
        };
        let mut refs = vec![];
        let first_ref = String::from_utf8_lossy(&first_ref);
        let (head_ref, capabilities) = first_ref
            .split_once('\0')
            .ok_or(Error::msg("HEAD ref must contain capabilities"))?;
        let capabilities = capabilities.split(' ').map(|str| str.into()).collect();
        refs.push(Cow::Borrowed(head_ref).into());

        for git_ref in refs_iter {
            let str = String::from_utf8_lossy(&git_ref);
            refs.push(str.into())
        }
        Ok(Self { refs, capabilities })
    }
}

#[derive(Debug)]
struct Message(Vec<Bytes>);

#[derive(Debug)]
struct Ref {
    hash: String,
    name: String,
}

impl<'a> From<Cow<'a, str>> for Ref {
    fn from(value: Cow<'a, str>) -> Self {
        let (hash, name) = value
            .split_once(' ')
            .expect("Hash and name separated by space.");
        Self {
            hash: hash.into(),
            name: name.into(),
        }
    }
}

#[derive(Debug)]
enum PacketLine {
    SpecialPacket(SpecialPacket),
    Line(Bytes),
}

impl PacketLine {
    fn write_all<W: Write>(&self, buf: &mut W) -> Result<()> {
        let result = match self {
            PacketLine::SpecialPacket(SpecialPacket::Flush) => {
                buf.write_all(hex::encode(0u16.to_be_bytes()).as_bytes())
            }
            PacketLine::SpecialPacket(SpecialPacket::Delimeter) => {
                buf.write_all(hex::encode(1u16.to_be_bytes()).as_bytes())
            }
            PacketLine::SpecialPacket(SpecialPacket::ResponseEnd) => {
                buf.write_all(hex::encode(2u16.to_be_bytes()).as_bytes())
            }
            PacketLine::Line(bytes) => {
                let length = (bytes.len() + 4) as u16;
                buf.write_all(hex::encode(length.to_be_bytes()).as_bytes())?;
                buf.write_all(bytes)
            }
        };
        result.map_err(Error::from)
    }
}

#[derive(Debug)]
enum SpecialPacket {
    Flush,
    Delimeter,
    ResponseEnd,
}

impl SpecialPacket {
    fn from(length: usize) -> Option<SpecialPacket> {
        match length {
            0 => Some(SpecialPacket::Flush),
            1 => Some(SpecialPacket::Delimeter),
            2 => Some(SpecialPacket::ResponseEnd),
            _ => None,
        }
    }
}

pub fn clone(repo_url: String, destination_dir: PathBuf) -> Result<()> {
    // init_repo(&destination_dir)?;
    let url = Url::parse(format!("{repo_url}/info/refs?service=git-upload-pack").as_str())?;
    let ls_refs_response = ls_refs(url)?;

    let url = Url::parse(format!("{repo_url}/git-upload-pack").as_str())?;
    fetch(
        url,
        &ls_refs_response.refs,
        &ls_refs_response.capabilities,
        &destination_dir,
    )?;
    write_refs(&ls_refs_response.refs, &destination_dir)?;
    let commit_object = CommitObject::parse(head_hash(&ls_refs_response.refs), &destination_dir)?;
    checkout_tree(commit_object.tree_hash.as_str(), &destination_dir)
}

fn checkout_tree(hash: &str, destination_dir: &PathBuf) -> Result<()> {
    let tree_nodes = TreeNode::read(hash, &destination_dir)?;
    for node in tree_nodes {
        let object = read_object(node.hash.as_str(), &destination_dir)?;
        let (content, header) = ObjectHeader::parse_bytes(object.as_slice())?;
        match header.object_type {
            ObjectType::Blob => {
                let mut file = std::fs::File::create(destination_dir.join(node.path))?;
                file.write_all(content)?;
            }
            ObjectType::Tree => {
                checkout_tree(node.hash.as_str(), &destination_dir)?;
            }
            ObjectType::Commit => return Err(Error::msg("Unexpected object type.")),
        }
    }
    Ok(())
}

fn head_hash(refs: &[Ref]) -> &str {
    let mut iter = refs.into_iter();
    let head_ref = iter.next().expect("HEAD ref does not exist.");

    iter.find_map(|git_ref| {
        if head_ref.name == git_ref.hash {
            Some(git_ref.hash.as_str())
        } else {
            None
        }
    })
    .unwrap_or(head_ref.hash.as_str())
}

fn write_refs<P: AsRef<Path>>(refs: &[Ref], destination_dir: P) -> Result<()> {
    let mut iter = refs.into_iter();
    let head_ref = iter
        .next()
        .ok_or_else(|| Error::msg("HEAD ref does not exist."))?;

    for git_ref in iter {
        if git_ref.name == head_ref.hash {
            println!("Write head");
            let mut head_file = std::fs::File::create(destination_dir.as_ref().join(".git/HEAD"))?;
            head_file.write_all(format!("ref: {}\n", git_ref.name).as_bytes())?;
        } else {
            let full_path = destination_dir
                .as_ref()
                .join(".git")
                .join(git_ref.name.as_str());
            let parent_dir = Path::new(&full_path)
                .parent()
                .ok_or_else(|| Error::msg("Failed to get parent dir."))?;

            std::fs::create_dir_all(parent_dir)?;
            let mut ref_file = std::fs::File::create(full_path)?;
            ref_file.write_all(git_ref.hash.as_bytes())?;
            ref_file.write_all(&[b'\n'])?;
        }
    }
    Ok(())
}

fn ls_refs(url: Url) -> Result<LsRefsResponse> {
    let bytes = Client::new()
        .get(url)
        .header(CONTENT_TYPE, GIT_UPLOAD_PACK_CONTENT_TYPE)
        .send()?
        .bytes()?;

    let messages = parse_ls_ref_response(bytes)?;
    messages.try_into()
}

const CLIENT_CAPABILITIES: [&str; 1] = ["side-band-64k"];
fn fetch<P: AsRef<Path>>(
    url: Url,
    refs: &[Ref],
    capabilities: &HashSet<String>,
    destination_dir: P,
) -> Result<()> {
    let mut refs_iter = refs.into_iter();
    let Some(first_ref) = refs_iter.next() else {
        return Ok(());
    };
    let mut body = vec![];
    let first_ref = CLIENT_CAPABILITIES
        .into_iter()
        .filter(|c| capabilities.contains(*c))
        .enumerate()
        .fold(
            format!("want {} ", first_ref.hash),
            |mut acc, (index, cap)| {
                if index == 0 {
                    acc.push_str(cap);
                } else {
                    acc.push(' ');
                    acc.push_str(cap);
                }
                acc
            },
        );
    PacketLine::Line(first_ref.into()).write_all(&mut body)?;

    for git_ref in refs_iter {
        PacketLine::Line(format!("want {}", git_ref.hash).into()).write_all(&mut body)?;
    }

    PacketLine::SpecialPacket(SpecialPacket::Flush).write_all(&mut body)?;
    PacketLine::Line("done".into()).write_all(&mut body)?;

    let response = Client::new()
        .post(url)
        .header(CONTENT_TYPE, GIT_UPLOAD_PACK_CONTENT_TYPE)
        .body(body)
        .send()?
        .error_for_status()?;

    FetchResponseReader::new(FetchResponseIterator::new(response)).start(destination_dir)
}

fn parse_ls_ref_response(bytes: Bytes) -> Result<Vec<Message>> {
    let mut messages = vec![];
    let mut message = vec![];
    let mut rest = bytes;
    while !rest.is_empty() {
        let (rest_bytes, line) = parse_packet_line(rest)?;
        rest = rest_bytes;
        match line {
            PacketLine::SpecialPacket(SpecialPacket::Flush) => {
                messages.push(Message(std::mem::take(&mut message)));
            }
            PacketLine::SpecialPacket(SpecialPacket::Delimeter) => {}
            PacketLine::SpecialPacket(SpecialPacket::ResponseEnd) => return Ok(messages),
            PacketLine::Line(line) => {
                message.push(line);
            }
        }
    }
    Ok(messages)
}

fn parse_packet_line(bytes: Bytes) -> Result<(Bytes, PacketLine)> {
    let length_str = hex::decode(&bytes[0..4])?;
    let length = i16::from_be_bytes(length_str.as_slice().try_into()?) as usize;
    match SpecialPacket::from(length) {
        Some(packet) => Ok((bytes.slice(4..), PacketLine::SpecialPacket(packet))),
        None => Ok((
            bytes.slice(length..),
            PacketLine::Line(bytes.slice(4..length)),
        )),
    }
}

#[derive(Debug)]
enum StreamCode {
    PackData,
    ProgressMessage,
    FatalError,
}

impl TryFrom<u8> for StreamCode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PackData),
            2 => Ok(Self::ProgressMessage),
            3 => Ok(StreamCode::FatalError),
            _ => Err(Error::msg(format!("Incorrent stream code {value}"))),
        }
    }
}

#[derive(Debug)]
enum StreamedPacketLine<'a> {
    SpecialPacket(SpecialPacket),
    Line(&'a [u8]),
}

struct FetchResponseIterator {
    response: Response,
}

impl FetchResponseIterator {
    fn new(response: Response) -> Self {
        Self { response }
    }
}

struct FetchResponseReader {
    iterator: FetchResponseIterator,
    buffer: Vec<u8>,
    start_index: usize,
    has_end_reached: bool,
}

impl FetchResponseReader {
    fn new(iterator: FetchResponseIterator) -> Self {
        Self {
            iterator,
            buffer: vec![],
            start_index: 0,
            has_end_reached: false,
        }
    }
    fn start<P: AsRef<Path>>(&mut self, destination_dir: P) -> Result<()> {
        loop {
            let mut initial_bytes = [0u8; 4];
            self.read_exact(&mut initial_bytes)?;
            if &initial_bytes != b"PACK" {
                let mut hash_bytes = [0u8; 20];
                hash_bytes[0..4].copy_from_slice(&initial_bytes);
                self.read_exact(&mut hash_bytes[4..])?;
                println!("Checksum: {}", hex::encode(&hash_bytes));
                return Ok(());
            }
            let objects_len = parse_pack_file_header(self)?;
            println!("Pack file parse. Number of objects: {objects_len}");

            for _ in 0..objects_len {
                ParsedObject::parse(self)?.write(&destination_dir)?;
            }
            println!("All of {objects_len} objects written.");
        }
    }
}

impl Read for FetchResponseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.start_index < self.buffer.len() {
            let len = self.buffer.len() - self.start_index;
            buf.copy_from_slice(&self.buffer[self.start_index..]);
            self.start_index = self.buffer.len();
            return Ok(len);
        }
        match self.iterator.next(&mut self.buffer)? {
            Some(_) => {
                buf.copy_from_slice(self.buffer.as_slice());
                self.start_index = 1;
                Ok(self.buffer.len())
            }
            None => {
                self.has_end_reached = true;
                Ok(0)
            }
        }
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut rest = self.buffer.len() - self.start_index;
        if rest >= buf.len() {
            let start = self.start_index;
            self.start_index += buf.len();
            buf.copy_from_slice(&self.buffer[start..self.start_index]);
            return Ok(());
        }
        if rest > 0 {
            buf[0..rest].copy_from_slice(&self.buffer[self.start_index..]);
        }
        self.start_index = self.buffer.len();
        loop {
            match self.iterator.next(&mut self.buffer)? {
                Some(_) => {
                    let end_index = self.buffer.len().min(buf.len() - rest + 1);
                    let slice = &self.buffer[1..end_index];
                    buf[rest..rest + slice.len()].copy_from_slice(slice);
                    self.start_index = end_index;
                    rest += slice.len();
                    if rest == buf.len() {
                        return Ok(());
                    }
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Unable to fill the buffer.",
                    ))
                }
            }
        }
    }
}

impl BufRead for FetchResponseReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.buffer.is_empty() || self.buffer.len() <= self.start_index {
            let result = self
                .iterator
                .next(&mut self.buffer)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            match result {
                Some(_) => {
                    self.start_index = 1;
                }
                None => {
                    self.has_end_reached = true;
                }
            }
        }
        Ok(&self.buffer[self.start_index..])
    }
    fn consume(&mut self, amt: usize) {
        assert!(self.start_index + amt <= self.buffer.len());
        self.start_index = self.start_index + amt;
    }
}

impl FetchResponseIterator {
    fn next(&mut self, buf: &mut Vec<u8>) -> std::result::Result<Option<()>, std::io::Error> {
        loop {
            let line = parse_packet_line_stream(&mut self.response, buf)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            match line {
                StreamedPacketLine::SpecialPacket(SpecialPacket::Flush) => {}
                StreamedPacketLine::SpecialPacket(SpecialPacket::Delimeter) => {}
                StreamedPacketLine::SpecialPacket(SpecialPacket::ResponseEnd) => break Ok(None),
                StreamedPacketLine::Line(line) if line.is_empty() => break Ok(None),
                StreamedPacketLine::Line(line) if line == b"NAK\n" => {}
                StreamedPacketLine::Line(line) => {
                    let stream_code = line[0].try_into().expect("Invalid stream code.");
                    match stream_code {
                        StreamCode::FatalError => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Fatal error stream code received.",
                            ));
                        }
                        StreamCode::ProgressMessage => String::from_utf8_lossy(&line[1..])
                            .split('\r')
                            .filter(|l| !l.is_empty())
                            .for_each(|l| {
                                println!("{}", l);
                            }),
                        StreamCode::PackData => {
                            break Ok(Some(()));
                        }
                    }
                }
            }
        }
    }
}

fn parse_packet_line_stream<'a, R: Read>(
    reader: &'a mut R,
    mut buffer: &'a mut Vec<u8>,
) -> Result<StreamedPacketLine<'a>> {
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length_str = hex::decode(length_bytes)?;
    let length = i16::from_be_bytes(length_str.as_slice().try_into()?) as usize;
    match SpecialPacket::from(length) {
        Some(packet) => Ok(StreamedPacketLine::SpecialPacket(packet)),
        None => {
            buffer.clear();
            buffer.resize(length - 4, 0);
            reader.read_exact(&mut buffer)?;
            Ok(StreamedPacketLine::Line(buffer))
        }
    }
}

fn parse_pack_file_header<R: Read>(reader: &mut R) -> Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    let verison = u32::from_be_bytes(buf);
    assert!(verison == 2 || verison == 3);

    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf) as usize)
}

enum ParsedObject {
    Base {
        object_type: ObjectType,
        data: Vec<u8>,
    },
    Delta {
        hash: String,
        delta: Vec<u8>,
    },
}

#[derive(Debug)]
enum ParsedObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ParsedObject {
    fn parse<R: BufRead>(reader: &mut R) -> Result<Self> {
        let (object_type, len) = parse_object_type_and_entries_len(reader)?;
        match object_type {
            ParsedObjectType::RefDelta => {
                let mut hash = [0u8; 20];
                reader.read_exact(&mut hash)?;
                let hash = hex::encode(&hash);
                let mut decoder = ZlibDecoder::new(reader);
                let mut delta = Vec::with_capacity(len);
                decoder.read_to_end(&mut delta)?;
                assert_eq!(delta.len(), len);
                Ok(ParsedObject::Delta { hash, delta })
            }
            ParsedObjectType::OfsDelta => {
                todo!("Not supported yet.")
            }
            ParsedObjectType::Commit
            | ParsedObjectType::Tree
            | ParsedObjectType::Blob
            | ParsedObjectType::Tag => {
                let mut decoder = ZlibDecoder::new(reader);
                let mut data = Vec::with_capacity(len);
                decoder.read_to_end(&mut data)?;
                Ok(ParsedObject::Base {
                    object_type: object_type.into(),
                    data,
                })
            }
        }
    }

    fn write<P: AsRef<Path>>(self, destination_dir: P) -> Result<String> {
        let (header, content) = match self {
            ParsedObject::Base { object_type, data } => {
                let header = ObjectHeader::new(object_type, data.len() as u64);
                (header, data)
            }
            ParsedObject::Delta { hash, delta } => {
                let base_object = read_object(hash.as_str(), &destination_dir)?;
                let (content, header) = ObjectHeader::parse_bytes(base_object.as_slice())?;
                let reconstracted = apply_delta(delta.as_slice(), content)?;
                let header = ObjectHeader::new(header.object_type, reconstracted.len() as u64);
                (header, reconstracted)
            }
        };
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
            root_dir: destination_dir.as_ref().into(),
        };
        object.write()
    }
}

impl Into<ObjectType> for ParsedObjectType {
    fn into(self) -> ObjectType {
        match self {
            Self::Blob => ObjectType::Blob,
            Self::Commit => ObjectType::Commit,
            Self::Tree => ObjectType::Tree,
            _ => panic!("Unsupprted object type."),
        }
    }
}

impl TryFrom<u8> for ParsedObjectType {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            6 => Ok(Self::OfsDelta),
            7 => Ok(Self::RefDelta),
            _ => Err(Error::msg(format!("Unexpected object type {value}"))),
        }
    }
}

fn parse_object_type_and_entries_len<R: Read>(reader: &mut R) -> Result<(ParsedObjectType, usize)> {
    let mut one_byte = [0u8; 1];
    let mut offset = 0;
    let mut entries_len = 0usize;
    let mut object_type = None;
    loop {
        reader.read_exact(&mut one_byte)?;
        let byte = one_byte[0];
        if object_type.is_none() {
            object_type = Some(((byte & 0b01110000) >> 4).try_into()?);
            entries_len = (byte & 0b00001111) as usize;
            offset += 4;
        } else {
            entries_len |= ((byte & 0b01111111) as usize) << offset;
            offset += 7;
        }
        if byte <= 127 {
            return Ok((object_type.unwrap(), entries_len));
        }
    }
}

const COPY_MODE: u8 = 0b10000000;
const SIZE_BITS: u8 = 0b0111000;
const OFFSET_BITS: u8 = 0b000001111;
fn apply_delta(delta: &[u8], base: &[u8]) -> Result<Vec<u8>> {
    let (delta, base_len) = read_variable_length(&delta)?;
    let (mut delta, reconstracted_len) = read_variable_length(&delta)?;
    assert!(base_len == base.len());

    let mut reconstracted = Vec::with_capacity(reconstracted_len);

    while !delta.is_empty() {
        let instruction = delta[0];
        if instruction & COPY_MODE != 0 {
            let (rest, offset) = decode_usize(&delta[1..], instruction & OFFSET_BITS);
            let (rest, size) = decode_usize(rest, (instruction & SIZE_BITS) >> 4);
            reconstracted.write(&base[offset..offset + size])?;
            delta = rest;
        } else {
            let size = usize::from(instruction);
            reconstracted.write(&delta[1..size + 1])?;
            delta = &delta[size + 1..];
        }
    }
    assert_eq!(reconstracted.len(), reconstracted_len);
    Ok(reconstracted)
}

fn read_variable_length(buf: &[u8]) -> Result<(&[u8], usize)> {
    let mut index = 0;
    let mut offset = 0;
    let mut length = 0usize;
    loop {
        let byte = buf[index];
        length |= ((byte & 0b01111111) as usize) << offset;
        offset += 7;
        index += 1;
        if byte <= 127 {
            return Ok((&buf[index..], length));
        }
    }
}

fn decode_usize(buf: &[u8], instruction: u8) -> (&[u8], usize) {
    let mut len_bytes: [u8; 8] = [0; 8];
    let mut buf = buf;
    for index in 0..len_bytes.len() {
        let offset = (instruction >> index) & 1;
        if offset == 1 {
            len_bytes[index] = buf[0];
            buf = &buf[1..];
        }
    }
    (buf, usize::from_le_bytes(len_bytes))
}

fn read_object<P: AsRef<Path>>(hash: &str, root_dir: P) -> Result<Vec<u8>> {
    let file_path = root_dir
        .as_ref()
        .join(".git/objects")
        .join(&hash[0..2])
        .join(&hash[2..]);
    let file_content = std::fs::read(file_path)?;
    let mut decoder = flate2::read::ZlibDecoder::new(file_content.as_slice());

    let mut result = vec![];
    decoder.read_to_end(&mut result)?;
    Ok(result)
}
