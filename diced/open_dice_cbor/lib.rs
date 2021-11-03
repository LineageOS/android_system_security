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

//! Implements safe wrappers around the public API of libopen-dice.
//! ## Example:
//! ```
//! use diced_open_dice_cbor as dice;
//!
//! let context = dice::dice::OpenDiceCborContext::new()
//! let parent_cdi_attest = [1u8, dice::CDI_SIZE];
//! let parent_cdi_seal = [2u8, dice::CDI_SIZE];
//! let input_values = dice::InputValuesOwned {
//!     code_hash: [3u8, dice::HASH_SIZE],
//!     config: dice::ConfigOwned::Descriptor("My descriptor".as_bytes().to_vec()),
//!     authority_hash: [0u8, dice::HASH_SIZE],
//!     mode: dice::Mode::Normal,
//!     hidden: [0u8, dice::HIDDEN_SIZE],
//! };
//! let (cdi_attest, cdi_seal, cert_chain) = context
//!     .main_flow(&parent_cdi_attest, &parent_cdi_seal, &input_values)?;
//! ```

use keystore2_crypto::{zvec, ZVec};
use open_dice_bcc_bindgen::BccMainFlow;
use open_dice_cbor_bindgen::{
    DiceConfigType, DiceDeriveCdiCertificateId, DiceDeriveCdiPrivateKeySeed,
    DiceGenerateCertificate, DiceHash, DiceInputValues, DiceKdf, DiceKeypairFromSeed, DiceMainFlow,
    DiceMode, DiceResult, DiceSign, DiceVerify, DICE_CDI_SIZE, DICE_HASH_SIZE, DICE_HIDDEN_SIZE,
    DICE_ID_SIZE, DICE_INLINE_CONFIG_SIZE, DICE_PRIVATE_KEY_SEED_SIZE, DICE_PRIVATE_KEY_SIZE,
    DICE_PUBLIC_KEY_SIZE, DICE_SIGNATURE_SIZE,
};
use open_dice_cbor_bindgen::{
    DiceConfigType_kDiceConfigTypeDescriptor as DICE_CONFIG_TYPE_DESCRIPTOR,
    DiceConfigType_kDiceConfigTypeInline as DICE_CONFIG_TYPE_INLINE,
    DiceMode_kDiceModeDebug as DICE_MODE_DEBUG,
    DiceMode_kDiceModeMaintenance as DICE_MODE_RECOVERY,
    DiceMode_kDiceModeNormal as DICE_MODE_NORMAL,
    DiceMode_kDiceModeNotInitialized as DICE_MODE_NOT_CONFIGURED,
    DiceResult_kDiceResultBufferTooSmall as DICE_RESULT_BUFFER_TOO_SMALL,
    DiceResult_kDiceResultInvalidInput as DICE_RESULT_INVALID_INPUT,
    DiceResult_kDiceResultOk as DICE_RESULT_OK,
    DiceResult_kDiceResultPlatformError as DICE_RESULT_PLATFORM_ERROR,
};
use std::ffi::{c_void, NulError};

/// The size of a DICE hash.
pub const HASH_SIZE: usize = DICE_HASH_SIZE as usize;
/// The size of the DICE hidden value.
pub const HIDDEN_SIZE: usize = DICE_HIDDEN_SIZE as usize;
/// The size of a DICE inline config.
pub const INLINE_CONFIG_SIZE: usize = DICE_INLINE_CONFIG_SIZE as usize;
/// The size of a private key seed.
pub const PRIVATE_KEY_SEED_SIZE: usize = DICE_PRIVATE_KEY_SEED_SIZE as usize;
/// The size of a CDI.
pub const CDI_SIZE: usize = DICE_CDI_SIZE as usize;
/// The size of an ID.
pub const ID_SIZE: usize = DICE_ID_SIZE as usize;
/// The size of a private key.
pub const PRIVATE_KEY_SIZE: usize = DICE_PRIVATE_KEY_SIZE as usize;
/// The size of a public key.
pub const PUBLIC_KEY_SIZE: usize = DICE_PUBLIC_KEY_SIZE as usize;
/// The size of a signature.
pub const SIGNATURE_SIZE: usize = DICE_SIGNATURE_SIZE as usize;

/// Open dice wrapper error type.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// The libopen-dice backend reported InvalidInput.
    #[error("Open dice backend: Invalid input")]
    InvalidInput,
    /// The libopen-dice backend reported BufferTooSmall.
    #[error("Open dice backend: Buffer too small")]
    BufferTooSmall,
    /// The libopen-dice backend reported PlatformError.
    #[error("Open dice backend: Platform error")]
    PlatformError,
    /// The libopen-dice backend reported an error that is outside of the defined range of errors.
    /// The returned error code is embedded in this value.
    #[error("Open dice backend returned an unexpected error code: {0:?}")]
    Unexpected(u32),

    /// The allocation of a ZVec failed. Most likely due to a failure during the call to mlock.
    #[error("ZVec allocation failed")]
    ZVec(#[from] zvec::Error),

    /// Functions that have to convert str to CString may fail if the string has an interior
    /// nul byte.
    #[error("Input string has an interior nul byte.")]
    CStrNulError(#[from] NulError),
}

/// Open dice result type.
pub type Result<T> = std::result::Result<T, Error>;

impl From<DiceResult> for Error {
    fn from(result: DiceResult) -> Self {
        match result {
            DICE_RESULT_INVALID_INPUT => Error::InvalidInput,
            DICE_RESULT_BUFFER_TOO_SMALL => Error::BufferTooSmall,
            DICE_RESULT_PLATFORM_ERROR => Error::PlatformError,
            r => Error::Unexpected(r),
        }
    }
}

fn check_result(result: DiceResult) -> Result<()> {
    if result == DICE_RESULT_OK {
        Ok(())
    } else {
        Err(result.into())
    }
}

/// Configuration descriptor for dice input values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Config<'a> {
    /// A reference to an inline descriptor.
    Inline(&'a [u8; INLINE_CONFIG_SIZE]),
    /// A reference to a free form descriptor that will be hashed by the implementation.
    Descriptor(&'a [u8]),
}

enum ConfigOwned {
    Inline([u8; INLINE_CONFIG_SIZE]),
    Descriptor(Vec<u8>),
}

impl Config<'_> {
    fn get_type(&self) -> DiceConfigType {
        match self {
            Self::Inline(_) => DICE_CONFIG_TYPE_INLINE,
            Self::Descriptor(_) => DICE_CONFIG_TYPE_DESCRIPTOR,
        }
    }

    fn get_inline(&self) -> [u8; INLINE_CONFIG_SIZE] {
        match self {
            Self::Inline(inline) => **inline,
            _ => [0u8; INLINE_CONFIG_SIZE],
        }
    }

    fn get_descriptor_as_ptr(&self) -> *const u8 {
        match self {
            Self::Descriptor(descriptor) => descriptor.as_ptr(),
            _ => std::ptr::null(),
        }
    }

    fn get_descriptor_size(&self) -> usize {
        match self {
            Self::Descriptor(descriptor) => descriptor.len(),
            _ => 0,
        }
    }
}

impl From<Config<'_>> for ConfigOwned {
    fn from(config: Config) -> Self {
        match config {
            Config::Inline(inline) => ConfigOwned::Inline(*inline),
            Config::Descriptor(descriptor) => ConfigOwned::Descriptor(descriptor.to_owned()),
        }
    }
}

/// DICE modes as defined here:
/// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#mode-value-details
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// See documentation linked above.
    NotConfigured = 0,
    /// See documentation linked above.
    Normal = 1,
    /// See documentation linked above.
    Debug = 2,
    /// See documentation linked above.
    Recovery = 3,
}

impl Mode {
    fn get_internal(&self) -> DiceMode {
        match self {
            Self::NotConfigured => DICE_MODE_NOT_CONFIGURED,
            Self::Normal => DICE_MODE_NORMAL,
            Self::Debug => DICE_MODE_DEBUG,
            Self::Recovery => DICE_MODE_RECOVERY,
        }
    }
}

/// This trait allows API users to supply DICE input values without copying.
pub trait InputValues {
    /// Returns the code hash.
    fn code_hash(&self) -> &[u8; HASH_SIZE];
    /// Returns the config.
    fn config(&self) -> Config;
    /// Returns the authority hash.
    fn authority_hash(&self) -> &[u8; HASH_SIZE];
    /// Returns the authority descriptor.
    fn authority_descriptor(&self) -> Option<&[u8]>;
    /// Returns the mode.
    fn mode(&self) -> Mode;
    /// Returns the hidden value.
    fn hidden(&self) -> &[u8; HIDDEN_SIZE];
}

/// An owning convenience type implementing `InputValues`.
pub struct InputValuesOwned {
    code_hash: [u8; HASH_SIZE],
    config: ConfigOwned,
    authority_hash: [u8; HASH_SIZE],
    authority_descriptor: Option<Vec<u8>>,
    mode: Mode,
    hidden: [u8; HIDDEN_SIZE],
}

impl InputValuesOwned {
    /// Construct a new instance of InputValuesOwned.
    pub fn new(
        code_hash: [u8; HASH_SIZE],
        config: Config,
        authority_hash: [u8; HASH_SIZE],
        authority_descriptor: Option<Vec<u8>>,
        mode: Mode,
        hidden: [u8; HIDDEN_SIZE],
    ) -> Self {
        Self {
            code_hash,
            config: config.into(),
            authority_hash,
            authority_descriptor,
            mode,
            hidden,
        }
    }
}

impl InputValues for InputValuesOwned {
    fn code_hash(&self) -> &[u8; HASH_SIZE] {
        &self.code_hash
    }
    fn config(&self) -> Config {
        match &self.config {
            ConfigOwned::Inline(inline) => Config::Inline(inline),
            ConfigOwned::Descriptor(descriptor) => Config::Descriptor(descriptor.as_slice()),
        }
    }
    fn authority_hash(&self) -> &[u8; HASH_SIZE] {
        &self.authority_hash
    }
    fn authority_descriptor(&self) -> Option<&[u8]> {
        self.authority_descriptor.as_deref()
    }
    fn mode(&self) -> Mode {
        self.mode
    }
    fn hidden(&self) -> &[u8; HIDDEN_SIZE] {
        &self.hidden
    }
}

fn call_with_input_values<T: InputValues + ?Sized, F, R>(input_values: &T, f: F) -> Result<R>
where
    F: FnOnce(*const DiceInputValues) -> Result<R>,
{
    let input_values = DiceInputValues {
        code_hash: *input_values.code_hash(),
        code_descriptor: std::ptr::null(),
        code_descriptor_size: 0,
        config_type: input_values.config().get_type(),
        config_value: input_values.config().get_inline(),
        config_descriptor: input_values.config().get_descriptor_as_ptr(),
        config_descriptor_size: input_values.config().get_descriptor_size(),
        authority_hash: *input_values.authority_hash(),
        authority_descriptor: input_values
            .authority_descriptor()
            .map_or_else(std::ptr::null, <[u8]>::as_ptr),
        authority_descriptor_size: input_values.authority_descriptor().map_or(0, <[u8]>::len),
        mode: input_values.mode().get_internal(),
        hidden: *input_values.hidden(),
    };

    f(&input_values as *const DiceInputValues)
}

/// Multiple of the open dice function required preallocated output buffer
/// which may be too small, this function implements the retry logic to handle
/// too small buffer allocations.
/// The callback `F` must expect a mutable reference to a buffer and a size hint
/// field. The callback is called repeatedly as long as it returns
/// `Err(Error::BufferTooSmall)`. If the size hint remains 0, the buffer size is
/// doubled with each iteration. If the size hint is set by the callback, the buffer
/// will be set to accommodate at least this many bytes.
/// If the callback returns `Ok(())`, the buffer is truncated to the size hint
/// exactly.
/// The function panics if the callback returns `Ok(())` and the size hint is
/// larger than the buffer size.
fn retry_while_adjusting_output_buffer<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(&mut Vec<u8>, &mut usize) -> Result<()>,
{
    let mut buffer = vec![0; INITIAL_OUT_BUFFER_SIZE];
    let mut actual_size: usize = 0;
    loop {
        match f(&mut buffer, &mut actual_size) {
            // If Error::BufferTooSmall was returned, the allocated certificate
            // buffer was to small for the output. So the buffer is resized to the actual
            // size, and a second attempt is made with the new buffer.
            Err(Error::BufferTooSmall) => {
                let new_size = if actual_size == 0 {
                    // Due to an off spec implementation of open dice cbor, actual size
                    // does not return the required size if the buffer was too small. So
                    // we have to try and approach it gradually.
                    buffer.len() * 2
                } else {
                    actual_size
                };
                buffer.resize(new_size, 0);
                continue;
            }
            Err(e) => return Err(e),
            Ok(()) => {
                if actual_size > buffer.len() {
                    panic!(
                        "actual_size larger than buffer size: open-dice function
                         may have written past the end of the buffer."
                    );
                }
                // Truncate the certificate buffer to the actual size because it may be
                // smaller than the original allocation.
                buffer.truncate(actual_size);
                return Ok(buffer);
            }
        }
    }
}

/// Some libopen-dice variants use a context. Developers that want to customize these
/// bindings may want to implement their own Context factory that creates a context
/// useable by their preferred backend.
pub trait Context {
    /// # Safety
    /// The return value of get_context is passed to any open dice function.
    /// Implementations must explain why the context pointer returned is safe
    /// to be used by the open dice library.
    unsafe fn get_context(&mut self) -> *mut c_void;
}

impl<T: Context + Send> ContextImpl for T {}

/// This represents a context for the open dice library. The wrapped open dice instance, which
/// is based on boringssl and cbor, does not use a context, so that this type is empty.
#[derive(Default)]
pub struct OpenDiceCborContext();

impl OpenDiceCborContext {
    /// Construct a new instance of OpenDiceCborContext.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Context for OpenDiceCborContext {
    unsafe fn get_context(&mut self) -> *mut c_void {
        // # Safety
        // The open dice cbor implementation does not use a context. It is safe
        // to return NULL.
        std::ptr::null_mut()
    }
}

/// Type alias for ZVec indicating that it holds a CDI_ATTEST secret.
pub type CdiAttest = ZVec;

/// Type alias for ZVec indicating that it holds a CDI_SEAL secret.
pub type CdiSeal = ZVec;

/// Type alias for Vec<u8> indicating that it hold a DICE certificate.
pub type Cert = Vec<u8>;

/// Type alias for Vec<u8> indicating that it holds a BCC certificate chain.
pub type Bcc = Vec<u8>;

const INITIAL_OUT_BUFFER_SIZE: usize = 1024;

/// ContextImpl is a mixin trait that implements the safe wrappers around the open dice
/// library calls. Implementations must implement Context::get_context(). As of
/// this writing, the only implementation is OpenDiceCborContext, which returns NULL.
pub trait ContextImpl: Context + Send {
    /// Safe wrapper around open-dice DiceDeriveCdiPrivateKeySeed, see open dice
    /// documentation for details.
    fn derive_cdi_private_key_seed(&mut self, cdi_attest: &[u8; CDI_SIZE]) -> Result<ZVec> {
        let mut seed = ZVec::new(PRIVATE_KEY_SEED_SIZE)?;
        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument is expected to be a const array of size CDI_SIZE.
        // * The third argument is expected to be a non const array of size
        //   PRIVATE_KEY_SEED_SIZE which is fulfilled if the call to ZVec::new above
        //   succeeds.
        // * No pointers are expected to be valid beyond the scope of the function
        //   call.
        check_result(unsafe {
            DiceDeriveCdiPrivateKeySeed(self.get_context(), cdi_attest.as_ptr(), seed.as_mut_ptr())
        })?;
        Ok(seed)
    }

    /// Safe wrapper around open-dice DiceDeriveCdiCertificateId, see open dice
    /// documentation for details.
    fn derive_cdi_certificate_id(&mut self, cdi_public_key: &[u8]) -> Result<ZVec> {
        let mut id = ZVec::new(ID_SIZE)?;
        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument is expected to be a const array with a size given by the
        //   third argument.
        // * The fourth argument is expected to be a non const array of size
        //   ID_SIZE which is fulfilled if the call to ZVec::new above succeeds.
        // * No pointers are expected to be valid beyond the scope of the function
        //   call.
        check_result(unsafe {
            DiceDeriveCdiCertificateId(
                self.get_context(),
                cdi_public_key.as_ptr(),
                cdi_public_key.len(),
                id.as_mut_ptr(),
            )
        })?;
        Ok(id)
    }

    /// Safe wrapper around open-dice DiceMainFlow, see open dice
    /// documentation for details.
    /// Returns a tuple of:
    ///  * The next attestation CDI,
    ///  * the next seal CDI, and
    ///  * the next attestation certificate.
    /// `(next_attest_cdi, next_seal_cdi, next_attestation_cert)`
    fn main_flow<T: InputValues + ?Sized>(
        &mut self,
        current_cdi_attest: &[u8; CDI_SIZE],
        current_cdi_seal: &[u8; CDI_SIZE],
        input_values: &T,
    ) -> Result<(CdiAttest, CdiSeal, Cert)> {
        let mut next_attest = CdiAttest::new(CDI_SIZE)?;
        let mut next_seal = CdiSeal::new(CDI_SIZE)?;

        // SAFETY (DiceMainFlow):
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are const arrays of size CDI_SIZE.
        //   This is fulfilled as per the definition of the arguments `current_cdi_attest`
        //   and `current_cdi_seal.
        // * The fourth argument is a pointer to `DiceInputValues`. It, and its indirect
        //   references must be valid for the duration of the function call which
        //   is guaranteed by `call_with_input_values` which puts `DiceInputValues`
        //   on the stack and initializes it from the `input_values` argument which
        //   implements the `InputValues` trait.
        // * The fifth and sixth argument are the length of and the pointer to the
        //   allocated certificate buffer respectively. They are used to return
        //   the generated certificate.
        // * The seventh argument is a pointer to a mutable usize object. It is
        //   used to return the actual size of the output certificate.
        // * The eighth argument and the ninth argument are pointers to mutable buffers of size
        //   CDI_SIZE. This is fulfilled if the allocation above succeeded.
        // * No pointers are expected to be valid beyond the scope of the function
        //   call.
        call_with_input_values(input_values, |input_values| {
            let cert = retry_while_adjusting_output_buffer(|cert, actual_size| {
                check_result(unsafe {
                    DiceMainFlow(
                        self.get_context(),
                        current_cdi_attest.as_ptr(),
                        current_cdi_seal.as_ptr(),
                        input_values,
                        cert.len(),
                        cert.as_mut_ptr(),
                        actual_size as *mut _,
                        next_attest.as_mut_ptr(),
                        next_seal.as_mut_ptr(),
                    )
                })
            })?;
            Ok((next_attest, next_seal, cert))
        })
    }

    /// Safe wrapper around open-dice DiceHash, see open dice
    /// documentation for details.
    fn hash(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output: Vec<u8> = vec![0; HASH_SIZE];

        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are the pointer to and length of the given
        //   input buffer respectively.
        // * The fourth argument must be a pointer to a mutable buffer of size HASH_SIZE
        //   which is fulfilled by the allocation above.
        check_result(unsafe {
            DiceHash(self.get_context(), input.as_ptr(), input.len(), output.as_mut_ptr())
        })?;
        Ok(output)
    }

    /// Safe wrapper around open-dice DiceKdf, see open dice
    /// documentation for details.
    fn kdf(&mut self, length: usize, input_key: &[u8], salt: &[u8], info: &[u8]) -> Result<ZVec> {
        let mut output = ZVec::new(length)?;

        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument is primitive.
        // * The third argument and the fourth argument are the pointer to and length of the given
        //   input key.
        // * The fifth argument and the sixth argument are the pointer to and length of the given
        //   salt.
        // * The seventh argument and the eighth argument are the pointer to and length of the
        //   given info field.
        // * The ninth argument is a pointer to the output buffer which must have the
        //   length given by the `length` argument (see second argument). This is
        //   fulfilled if the allocation of `output` succeeds.
        // * All pointers must be valid for the duration of the function call, but not
        //   longer.
        check_result(unsafe {
            DiceKdf(
                self.get_context(),
                length,
                input_key.as_ptr(),
                input_key.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output.as_mut_ptr(),
            )
        })?;
        Ok(output)
    }

    /// Safe wrapper around open-dice DiceKeyPairFromSeed, see open dice
    /// documentation for details.
    fn keypair_from_seed(&mut self, seed: &[u8; PRIVATE_KEY_SEED_SIZE]) -> Result<(Vec<u8>, ZVec)> {
        let mut private_key = ZVec::new(PRIVATE_KEY_SIZE)?;
        let mut public_key = vec![0u8; PUBLIC_KEY_SIZE];

        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument is a pointer to a const buffer of size `PRIVATE_KEY_SEED_SIZE`
        //   fulfilled by the definition of the argument.
        // * The third argument and the fourth argument are mutable buffers of size
        //   `PRIVATE_KEY_SIZE` and `PUBLIC_KEY_SIZE` respectively. This is fulfilled by the
        //   allocations above.
        // * All pointers must be valid for the duration of the function call but not beyond.
        check_result(unsafe {
            DiceKeypairFromSeed(
                self.get_context(),
                seed.as_ptr(),
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
            )
        })?;
        Ok((public_key, private_key))
    }

    /// Safe wrapper around open-dice DiceSign, see open dice
    /// documentation for details.
    fn sign(&mut self, message: &[u8], private_key: &[u8; PRIVATE_KEY_SIZE]) -> Result<Vec<u8>> {
        let mut signature = vec![0u8; SIGNATURE_SIZE];

        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are the pointer to and length of the given
        //   message buffer.
        // * The fourth argument is a const buffer of size `PRIVATE_KEY_SIZE`. This is fulfilled
        //   by the definition of `private key`.
        // * The fifth argument is mutable buffer of size `SIGNATURE_SIZE`. This is fulfilled
        //   by the allocation above.
        // * All pointers must be valid for the duration of the function call but not beyond.
        check_result(unsafe {
            DiceSign(
                self.get_context(),
                message.as_ptr(),
                message.len(),
                private_key.as_ptr(),
                signature.as_mut_ptr(),
            )
        })?;
        Ok(signature)
    }

    /// Safe wrapper around open-dice DiceVerify, see open dice
    /// documentation for details.
    fn verify(
        &mut self,
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
        public_key: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<()> {
        // SAFETY:
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are the pointer to and length of the given
        //   message buffer.
        // * The fourth argument is a const buffer of size `SIGNATURE_SIZE`. This is fulfilled
        //   by the definition of `signature`.
        // * The fifth argument is a const buffer of size `PUBLIC_KEY_SIZE`. This is fulfilled
        //   by the definition of `public_key`.
        // * All pointers must be valid for the duration of the function call but not beyond.
        check_result(unsafe {
            DiceVerify(
                self.get_context(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                public_key.as_ptr(),
            )
        })
    }

    /// Safe wrapper around open-dice DiceGenerateCertificate, see open dice
    /// documentation for details.
    fn generate_certificate<T: InputValues>(
        &mut self,
        subject_private_key_seed: &[u8; PRIVATE_KEY_SEED_SIZE],
        authority_private_key_seed: &[u8; PRIVATE_KEY_SEED_SIZE],
        input_values: &T,
    ) -> Result<Vec<u8>> {
        // SAFETY (DiceMainFlow):
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are const arrays of size
        //   `PRIVATE_KEY_SEED_SIZE`. This is fulfilled as per the definition of the arguments.
        // * The fourth argument is a pointer to `DiceInputValues` it, and its indirect
        //   references must be valid for the duration of the function call which
        //   is guaranteed by `call_with_input_values` which puts `DiceInputValues`
        //   on the stack and initializes it from the `input_values` argument which
        //   implements the `InputValues` trait.
        // * The fifth argument and the sixth argument are the length of and the pointer to the
        //   allocated certificate buffer respectively. They are used to return
        //   the generated certificate.
        // * The seventh argument is a pointer to a mutable usize object. It is
        //   used to return the actual size of the output certificate.
        // * All pointers must be valid for the duration of the function call but not beyond.
        call_with_input_values(input_values, |input_values| {
            let cert = retry_while_adjusting_output_buffer(|cert, actual_size| {
                check_result(unsafe {
                    DiceGenerateCertificate(
                        self.get_context(),
                        subject_private_key_seed.as_ptr(),
                        authority_private_key_seed.as_ptr(),
                        input_values,
                        cert.len(),
                        cert.as_mut_ptr(),
                        actual_size as *mut _,
                    )
                })
            })?;
            Ok(cert)
        })
    }

    /// Safe wrapper around open-dice BccDiceMainFlow, see open dice
    /// documentation for details.
    /// Returns a tuple of:
    ///  * The next attestation CDI,
    ///  * the next seal CDI, and
    ///  * the next bcc adding the new certificate to the given bcc.
    /// `(next_attest_cdi, next_seal_cdi, next_bcc)`
    fn bcc_main_flow<T: InputValues + ?Sized>(
        &mut self,
        current_cdi_attest: &[u8; CDI_SIZE],
        current_cdi_seal: &[u8; CDI_SIZE],
        bcc: &[u8],
        input_values: &T,
    ) -> Result<(CdiAttest, CdiSeal, Bcc)> {
        let mut next_attest = CdiAttest::new(CDI_SIZE)?;
        let mut next_seal = CdiSeal::new(CDI_SIZE)?;

        // SAFETY (BccMainFlow):
        // * The first context argument may be NULL and is unused by the wrapped
        //   implementation.
        // * The second argument and the third argument are const arrays of size CDI_SIZE.
        //   This is fulfilled as per the definition of the arguments `current_cdi_attest`
        //   and `current_cdi_seal`.
        // * The fourth argument and the fifth argument are the pointer to and size of the buffer
        //   holding the current bcc.
        // * The sixth argument is a pointer to `DiceInputValues` it, and its indirect
        //   references must be valid for the duration of the function call which
        //   is guaranteed by `call_with_input_values` which puts `DiceInputValues`
        //   on the stack and initializes it from the `input_values` argument which
        //   implements the `InputValues` trait.
        // * The seventh argument and the eighth argument are the length of and the pointer to the
        //   allocated certificate buffer respectively. They are used to return the generated
        //   certificate.
        // * The ninth argument is a pointer to a mutable usize object. It is
        //   used to return the actual size of the output certificate.
        // * The tenth argument and the eleventh argument are pointers to mutable buffers of
        //   size CDI_SIZE. This is fulfilled if the allocation above succeeded.
        // * No pointers are expected to be valid beyond the scope of the function
        //   call.
        call_with_input_values(input_values, |input_values| {
            let next_bcc = retry_while_adjusting_output_buffer(|next_bcc, actual_size| {
                check_result(unsafe {
                    BccMainFlow(
                        self.get_context(),
                        current_cdi_attest.as_ptr(),
                        current_cdi_seal.as_ptr(),
                        bcc.as_ptr(),
                        bcc.len(),
                        input_values,
                        next_bcc.len(),
                        next_bcc.as_mut_ptr(),
                        actual_size as *mut _,
                        next_attest.as_mut_ptr(),
                        next_seal.as_mut_ptr(),
                    )
                })
            })?;
            Ok((next_attest, next_seal, next_bcc))
        })
    }
}

/// This submodule provides additional support for the Boot Certificate Chain (BCC)
/// specification.
/// See https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/ProtectedData.aidl
pub mod bcc {
    use super::{check_result, retry_while_adjusting_output_buffer, Result};
    use open_dice_bcc_bindgen::{
        BccConfigValues, BccFormatConfigDescriptor, BCC_INPUT_COMPONENT_NAME,
        BCC_INPUT_COMPONENT_VERSION, BCC_INPUT_RESETTABLE,
    };
    use std::ffi::CString;

    /// Safe wrapper around BccFormatConfigDescriptor, see open dice documentation for details.
    pub fn format_config_descriptor(
        component_name: Option<&str>,
        component_version: Option<u64>,
        resettable: bool,
    ) -> Result<Vec<u8>> {
        let component_name = match component_name {
            Some(n) => Some(CString::new(n)?),
            None => None,
        };
        let input = BccConfigValues {
            inputs: if component_name.is_some() { BCC_INPUT_COMPONENT_NAME } else { 0 }
                | if component_version.is_some() { BCC_INPUT_COMPONENT_VERSION } else { 0 }
                | if resettable { BCC_INPUT_RESETTABLE } else { 0 },
            // SAFETY: The as_ref() in the line below is vital to keep the component_name object
            //         alive. Removing as_ref will move the component_name and the pointer will
            //         become invalid after this statement.
            component_name: component_name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            component_version: component_version.unwrap_or(0),
        };

        // SAFETY:
        // * The first argument is a pointer to the BccConfigValues input assembled above.
        //   It and its indirections must be valid for the duration of the function call.
        // * The second argument and the third argument are the length of and the pointer to the
        //   allocated output buffer respectively. The buffer must be at least as long
        //   as indicated by the size argument.
        // * The forth argument is a pointer to the actual size returned by the function.
        // * All pointers must be valid for the duration of the function call but not beyond.
        retry_while_adjusting_output_buffer(|config_descriptor, actual_size| {
            check_result(unsafe {
                BccFormatConfigDescriptor(
                    &input as *const BccConfigValues,
                    config_descriptor.len(),
                    config_descriptor.as_mut_ptr(),
                    actual_size as *mut _,
                )
            })
        })
    }
}
