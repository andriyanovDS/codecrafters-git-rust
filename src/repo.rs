use anyhow::{Error, Result};
use std::{fs, path::Path};

pub fn init_repo<P: AsRef<Path>>(destination: P) -> Result<()> {
    let destination = destination.as_ref();
    if !destination.exists() {
        fs::create_dir(destination)?;
    }
    fs::create_dir(destination.join(".git"))?;
    fs::create_dir(destination.join(".git/objects"))?;
    fs::create_dir(destination.join(".git/refs"))?;
    fs::write(destination.join(".git/HEAD"), "ref: refs/heads/master\n").map_err(Error::from)
}
