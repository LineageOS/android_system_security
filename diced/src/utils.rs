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

//! Implements utility functions and types for diced and the dice HAL.

/// This submodule implements a limited set of CBOR generation functionality. Essentially,
/// a cbor header generator and some convenience functions for number and BSTR encoding.
pub mod cbor {
    use anyhow::{anyhow, Context, Result};
    use std::convert::TryInto;
    use std::io::Write;

    /// CBOR encodes a positive number.
    pub fn encode_number(n: u64, buffer: &mut dyn Write) -> Result<()> {
        encode_header(0, n, buffer)
    }

    /// CBOR encodes a binary string.
    pub fn encode_bstr(bstr: &[u8], buffer: &mut dyn Write) -> Result<()> {
        encode_header(
            2,
            bstr.len().try_into().context("In encode_bstr: Failed to convert usize to u64.")?,
            buffer,
        )
        .context("In encode_bstr: While writing header.")?;
        let written = buffer.write(bstr).context("In encode_bstr: While writing payload.")?;
        if written != bstr.len() {
            return Err(anyhow!("In encode_bstr: Buffer too small. ({}, {})", written, bstr.len()));
        }
        Ok(())
    }

    /// Formats a CBOR header. `t` is the type, and n is the header argument.
    pub fn encode_header(t: u8, n: u64, buffer: &mut dyn Write) -> Result<()> {
        match n {
            n if n < 24 => {
                let written =
                    buffer.write(&u8::to_be_bytes((t << 5) | (n as u8 & 0x1F))).with_context(
                        || format!("In encode_header: Failed to write header ({}, {})", t, n),
                    )?;
                if written != 1 {
                    return Err(anyhow!("In encode_header: Buffer to small. ({}, {})", t, n));
                }
            }
            n if n <= 0xFF => {
                let written =
                    buffer.write(&u8::to_be_bytes((t << 5) | (24u8 & 0x1F))).with_context(
                        || format!("In encode_header: Failed to write header ({}, {})", t, n),
                    )?;
                if written != 1 {
                    return Err(anyhow!("In encode_header: Buffer to small. ({}, {})", t, n));
                }
                let written = buffer.write(&u8::to_be_bytes(n as u8)).with_context(|| {
                    format!("In encode_header: Failed to write size ({}, {})", t, n)
                })?;
                if written != 1 {
                    return Err(anyhow!(
                        "In encode_header while writing size: Buffer to small. ({}, {})",
                        t,
                        n
                    ));
                }
            }
            n if n <= 0xFFFF => {
                let written =
                    buffer.write(&u8::to_be_bytes((t << 5) | (25u8 & 0x1F))).with_context(
                        || format!("In encode_header: Failed to write header ({}, {})", t, n),
                    )?;
                if written != 1 {
                    return Err(anyhow!("In encode_header: Buffer to small. ({}, {})", t, n));
                }
                let written = buffer.write(&u16::to_be_bytes(n as u16)).with_context(|| {
                    format!("In encode_header: Failed to write size ({}, {})", t, n)
                })?;
                if written != 2 {
                    return Err(anyhow!(
                        "In encode_header while writing size: Buffer to small. ({}, {})",
                        t,
                        n
                    ));
                }
            }
            n if n <= 0xFFFFFFFF => {
                let written =
                    buffer.write(&u8::to_be_bytes((t << 5) | (26u8 & 0x1F))).with_context(
                        || format!("In encode_header: Failed to write header ({}, {})", t, n),
                    )?;
                if written != 1 {
                    return Err(anyhow!("In encode_header: Buffer to small. ({}, {})", t, n));
                }
                let written = buffer.write(&u32::to_be_bytes(n as u32)).with_context(|| {
                    format!("In encode_header: Failed to write size ({}, {})", t, n)
                })?;
                if written != 4 {
                    return Err(anyhow!(
                        "In encode_header while writing size: Buffer to small. ({}, {})",
                        t,
                        n
                    ));
                }
            }
            n => {
                let written =
                    buffer.write(&u8::to_be_bytes((t << 5) | (27u8 & 0x1F))).with_context(
                        || format!("In encode_header: Failed to write header ({}, {})", t, n),
                    )?;
                if written != 1 {
                    return Err(anyhow!("In encode_header: Buffer to small. ({}, {})", t, n));
                }
                let written = buffer.write(&u64::to_be_bytes(n)).with_context(|| {
                    format!("In encode_header: Failed to write size ({}, {})", t, n)
                })?;
                if written != 8 {
                    return Err(anyhow!(
                        "In encode_header while writing size: Buffer to small. ({}, {})",
                        t,
                        n
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod test {
        use super::*;

        fn encode_header_helper(t: u8, n: u64) -> Vec<u8> {
            let mut b: Vec<u8> = vec![];
            encode_header(t, n, &mut b).unwrap();
            b
        }

        #[test]
        fn encode_header_test() {
            assert_eq!(&encode_header_helper(0, 0), &[0b000_00000]);
            assert_eq!(&encode_header_helper(0, 23), &[0b000_10111]);
            assert_eq!(&encode_header_helper(0, 24), &[0b000_11000, 24]);
            assert_eq!(&encode_header_helper(0, 0xff), &[0b000_11000, 0xff]);
            assert_eq!(&encode_header_helper(0, 0x100), &[0b000_11001, 0x01, 0x00]);
            assert_eq!(&encode_header_helper(0, 0xffff), &[0b000_11001, 0xff, 0xff]);
            assert_eq!(&encode_header_helper(0, 0x10000), &[0b000_11010, 0x00, 0x01, 0x00, 0x00]);
            assert_eq!(
                &encode_header_helper(0, 0xffffffff),
                &[0b000_11010, 0xff, 0xff, 0xff, 0xff]
            );
            assert_eq!(
                &encode_header_helper(0, 0x100000000),
                &[0b000_11011, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
            );
            assert_eq!(
                &encode_header_helper(0, 0xffffffffffffffff),
                &[0b000_11011, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            );
        }
    }
}
