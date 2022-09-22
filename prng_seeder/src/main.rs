// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! FIPS compliant random number conditioner. Reads from /dev/hw_random
//! and applies the NIST SP 800-90A CTR DRBG strategy to provide
//! pseudorandom bytes to clients which connect to a socket provided
//! by init.

mod conditioner;
mod cutils_socket;
mod drbg;

use std::{
    convert::Infallible,
    fs::{remove_file, File},
    io::ErrorKind,
    os::unix::{net::UnixListener, prelude::AsRawFd},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use nix::{
    fcntl::{fcntl, FcntlArg::F_SETFL, OFlag},
    sys::signal,
};
use tokio::{io::AsyncWriteExt, net::UnixListener as TokioUnixListener};

use crate::conditioner::Conditioner;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(long, default_value = "/dev/hw_random")]
    source: PathBuf,
    #[clap(long)]
    socket: Option<PathBuf>,
}

fn configure_logging() {
    logger::init(Default::default());
}

fn get_socket(path: &Path) -> Result<UnixListener> {
    if let Err(e) = remove_file(path) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e.into());
        }
    } else {
        info!("Deleted old {}", path.to_string_lossy());
    }
    Ok(UnixListener::bind(path)?)
}

async fn listen_loop(hwrng: File, listener: UnixListener) -> Result<Infallible> {
    let mut conditioner = Conditioner::new(hwrng)?;
    let listener = TokioUnixListener::from_std(listener)?;
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let new_bytes = conditioner.request()?;
                tokio::spawn(async move {
                    if let Err(e) = stream.write_all(&new_bytes).await {
                        error!("Request failed: {}", e);
                    }
                });
                conditioner.reseed_if_necessary().await?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn run(cli: Cli) -> Result<Infallible> {
    let hwrng = std::fs::File::open(&cli.source)?;
    fcntl(hwrng.as_raw_fd(), F_SETFL(OFlag::O_NONBLOCK))?;
    let listener = match cli.socket {
        Some(path) => get_socket(path.as_path())?,
        None => cutils_socket::android_get_control_socket("prng_seeder")?,
    };
    listener.set_nonblocking(true)?;

    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { listen_loop(hwrng, listener).await })
}

fn main() {
    let cli = Cli::parse();
    configure_logging();
    if let Err(e) = run(cli) {
        error!("Launch failed: {}", e);
    } else {
        error!("Loop terminated without an error")
    }
    std::process::exit(-1);
}
