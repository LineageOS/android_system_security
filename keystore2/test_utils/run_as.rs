// Copyright 2021, The Android Open Source Project
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

//! This module is intended for testing access control enforcement of services such as keystore2,
//! by assuming various identities with varying levels of privilege. Consequently, appropriate
//! privileges are required, or the attempt will fail causing a panic.
//! The `run_as` module provides the function `run_as`, which takes a UID, GID, an SELinux
//! context, and a closure. The return type of the closure, which is also the return type of
//! `run_as`, must implement `serde::Serialize` and `serde::Deserialize`.
//! `run_as` forks, transitions to the given identity, and executes the closure in the newly
//! forked process. If the closure returns, i.e., does not panic, the forked process exits with
//! a status of `0`, and the return value is serialized and sent through a pipe to the parent where
//! it gets deserialized and returned. The STDIO is not changed and the parent's panic handler
//! remains unchanged. So if the closure panics, the panic message is printed on the parent's STDERR
//! and the exit status is set to a non `0` value. The latter causes the parent to panic as well,
//! and if run in a test context, the test to fail.

use keystore2_selinux as selinux;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    close, fork, pipe as nix_pipe, read as nix_read, setgid, setuid, write as nix_write,
    ForkResult, Gid, Uid,
};
use serde::{de::DeserializeOwned, Serialize};
use std::os::unix::io::RawFd;

fn transition(se_context: selinux::Context, uid: Uid, gid: Gid) {
    setgid(gid).expect("Failed to set GID. This test might need more privileges.");
    setuid(uid).expect("Failed to set UID. This test might need more privileges.");

    selinux::setcon(&se_context)
        .expect("Failed to set SELinux context. This test might need more privileges.");
}

/// PipeReader is a simple wrapper around raw pipe file descriptors.
/// It takes ownership of the file descriptor and closes it on drop. It provides `read_all`, which
/// reads from the pipe into an expending vector, until no more data can be read.
struct PipeReader(RawFd);

impl PipeReader {
    pub fn read_all(&self) -> Result<Vec<u8>, nix::Error> {
        let mut buffer = [0u8; 128];
        let mut result = Vec::<u8>::new();
        loop {
            let bytes = nix_read(self.0, &mut buffer)?;
            if bytes == 0 {
                return Ok(result);
            }
            result.extend_from_slice(&buffer[0..bytes]);
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        close(self.0).expect("Failed to close reader pipe fd.");
    }
}

/// PipeWriter is a simple wrapper around raw pipe file descriptors.
/// It takes ownership of the file descriptor and closes it on drop. It provides `write`, which
/// writes the given buffer into the pipe, returning the number of bytes written.
struct PipeWriter(RawFd);

impl PipeWriter {
    pub fn write(&self, data: &[u8]) -> Result<usize, nix::Error> {
        nix_write(self.0, data)
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        close(self.0).expect("Failed to close writer pipe fd.");
    }
}

fn pipe() -> Result<(PipeReader, PipeWriter), nix::Error> {
    let (read_fd, write_fd) = nix_pipe()?;
    Ok((PipeReader(read_fd), PipeWriter(write_fd)))
}

/// Run the given closure in a new process running with the new identity given as
/// `uid`, `gid`, and `se_context`.
pub fn run_as<F, R>(se_context: &str, uid: Uid, gid: Gid, f: F) -> R
where
    R: Serialize + DeserializeOwned,
    F: 'static + Send + FnOnce() -> R,
{
    let se_context =
        selinux::Context::new(se_context).expect("Unable to construct selinux::Context.");
    let (reader, writer) = pipe().expect("Failed to create pipe.");

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            drop(writer);
            let status = waitpid(child, None).expect("Failed while waiting for child.");
            if let WaitStatus::Exited(_, 0) = status {
                // Child exited successfully.
                // Read the result from the pipe.
                let serialized_result =
                    reader.read_all().expect("Failed to read result from child.");

                // Deserialize the result and return it.
                serde_cbor::from_slice(&serialized_result).expect("Failed to deserialize result.")
            } else {
                panic!("Child did not exit as expected {:?}", status);
            }
        }
        Ok(ForkResult::Child) => {
            // This will panic on error or insufficient privileges.
            transition(se_context, uid, gid);

            // Run the closure.
            let result = f();

            // Serialize the result of the closure.
            let vec = serde_cbor::to_vec(&result).expect("Result serialization failed");

            // Send the result to the parent using the pipe.
            writer.write(&vec).expect("Failed to send serialized result to parent.");

            // Set exit status to `0`.
            std::process::exit(0);
        }
        Err(errno) => {
            panic!("Failed to fork: {:?}", errno);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use keystore2_selinux as selinux;
    use nix::unistd::{getgid, getuid};
    use serde::{Deserialize, Serialize};

    /// This test checks that the closure does not produce an exit status of `0` when run inside a
    /// test and the closure panics. This would mask test failures as success.
    #[test]
    #[should_panic]
    fn test_run_as_panics_on_closure_panic() {
        run_as(selinux::getcon().unwrap().to_str().unwrap(), getuid(), getgid(), || {
            panic!("Closure must panic.")
        });
    }

    static TARGET_UID: Uid = Uid::from_raw(10020);
    static TARGET_GID: Gid = Gid::from_raw(10020);
    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";

    /// Tests that the closure is running as the target identity.
    #[test]
    fn test_transition_to_untrusted_app() {
        run_as(TARGET_CTX, TARGET_UID, TARGET_GID, || {
            assert_eq!(TARGET_UID, getuid());
            assert_eq!(TARGET_GID, getgid());
            assert_eq!(TARGET_CTX, selinux::getcon().unwrap().to_str().unwrap());
        });
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct SomeResult {
        a: u32,
        b: u64,
        c: String,
    }

    #[test]
    fn test_serialized_result() {
        let test_result = SomeResult {
            a: 5,
            b: 0xffffffffffffffff,
            c: "supercalifragilisticexpialidocious".to_owned(),
        };
        let test_result_clone = test_result.clone();
        let result = run_as(TARGET_CTX, TARGET_UID, TARGET_GID, || test_result_clone);
        assert_eq!(test_result, result);
    }
}
