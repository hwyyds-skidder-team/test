//! Zero-dependency dynamic wrapper for Windows `fveapi.dll`.
//!
//! This crate intentionally models only the ABI that has been verified from
//! `fveapi.dll`: status probing, volume open/close, lock/unlock, and conversion
//! decrypt calls. `fveapi.dll` is undocumented, so status output is represented
//! as an aligned byte buffer and parsed by offsets guarded by the negotiated
//! structure size.

use std::ffi::c_void;
use std::fmt;

#[cfg(windows)]
use std::sync::OnceLock;

const MAX_STATUS_SIZE: usize = 0x80;
const FVE_FLAG_CHECK_MASK: u32 = 0x0000_017F;

const OFFSET_SIZE: usize = 0x00;
const OFFSET_VERSION: usize = 0x04;
const OFFSET_CONVERSION_STATUS: usize = 0x08;
const OFFSET_ENCRYPTION_FLAGS: usize = 0x0C;
const OFFSET_PERCENT_COMPLETE: usize = 0x10;
const OFFSET_LAST_ERROR: usize = 0x18;
const OFFSET_VOLUME_SIZE: usize = 0x20;
const OFFSET_WIPE_PERCENTAGE: usize = 0x28;
const OFFSET_FVEK_TYPE: usize = 0x30;
const OFFSET_ENCRYPTION_METHOD: usize = 0x34;
const OFFSET_EXTENDED_FLAGS: usize = 0x38;

#[cfg(any(windows, test))]
const FVE_AUTH_INFORMATION_SIZE: u32 = 0x38;
#[cfg(any(windows, test))]
const FVE_AUTH_INFORMATION_VERSION: u32 = 1;
#[cfg(any(windows, test))]
const FVE_AUTH_ELEMENT_VERSION: u32 = 1;
#[cfg(any(windows, test))]
const FVE_PASSPHRASE_AUTH_ELEMENT_SIZE: usize = 0x248;
#[cfg(any(windows, test))]
const FVE_RECOVERY_AUTH_ELEMENT_SIZE: usize = 0x20;

/// Known `FveGetStatus` layout versions, newest first.
///
/// IDA verification on current `fveapi.dll` shows version 9 / 0x80. Older
/// versions are kept for runtime negotiation because the DLL rejects layouts
/// newer than the host build with `E_INVALIDARG` (`0x80070057`).
pub const FVE_STATUS_LAYOUTS: [FveStatusLayout; 9] = [
    FveStatusLayout::new(9, 0x80),
    FveStatusLayout::new(8, 0x78),
    FveStatusLayout::new(7, 0x70),
    FveStatusLayout::new(6, 0x68),
    FveStatusLayout::new(5, 0x58),
    FveStatusLayout::new(4, 0x40),
    FveStatusLayout::new(3, 0x28),
    FveStatusLayout::new(2, 0x20),
    FveStatusLayout::new(1, 0x20),
];

/// Version/size pair accepted by `FveGetStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FveStatusLayout {
    /// `dwVersion` written at offset `+0x04`.
    pub version: u32,
    /// `dwSize` written at offset `+0x00`.
    pub size: u32,
}

impl FveStatusLayout {
    /// Creates a status layout descriptor.
    pub const fn new(version: u32, size: u32) -> Self {
        Self { version, size }
    }

    /// Returns whether the field range is covered by this layout.
    pub const fn contains(self, offset: usize, width: usize) -> bool {
        self.size as usize >= offset + width
    }
}

/// Aligned raw output buffer for `FveGetStatusW` / `FveGetStatus`.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct FveStatusBuffer {
    bytes: [u8; MAX_STATUS_SIZE],
}

impl FveStatusBuffer {
    /// Creates a zeroed status buffer and writes the requested layout header.
    pub fn new(layout: FveStatusLayout) -> Self {
        let mut buffer = Self {
            bytes: [0; MAX_STATUS_SIZE],
        };
        write_u32_at(&mut buffer.bytes, OFFSET_SIZE, layout.size);
        write_u32_at(&mut buffer.bytes, OFFSET_VERSION, layout.version);
        buffer
    }

    /// Returns the raw immutable bytes.
    pub fn bytes(&self) -> &[u8; MAX_STATUS_SIZE] {
        &self.bytes
    }

    #[cfg(windows)]
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.bytes.as_mut_ptr().cast::<c_void>()
    }

    fn read_u16(&self, layout: FveStatusLayout, offset: usize) -> Option<u16> {
        layout
            .contains(offset, 2)
            .then(|| read_u16_at(&self.bytes, offset))
    }

    fn read_u32(&self, layout: FveStatusLayout, offset: usize) -> Option<u32> {
        layout
            .contains(offset, 4)
            .then(|| read_u32_at(&self.bytes, offset))
    }

    fn read_u64(&self, layout: FveStatusLayout, offset: usize) -> Option<u64> {
        layout
            .contains(offset, 8)
            .then(|| read_u64_at(&self.bytes, offset))
    }

    fn read_f64(&self, layout: FveStatusLayout, offset: usize) -> Option<f64> {
        layout
            .contains(offset, 8)
            .then(|| f64::from_bits(read_u64_at(&self.bytes, offset)))
    }
}

/// `FveGetStatus` probe result.
#[derive(Debug, Clone, PartialEq)]
pub struct FveStatusProbe {
    /// First version/size pair not rejected by `E_INVALIDARG`.
    pub layout: FveStatusLayout,
    /// Raw HRESULT returned by `FveGetStatusW` for the accepted layout.
    ///
    /// `S_OK` means the status buffer was filled. Other business errors, for
    /// example "not encrypted", still prove the ABI layout was accepted.
    pub hresult: u32,
    /// Parsed status, present only when `hresult == 0`.
    pub status: Option<FveVolumeInfo>,
}

/// FVE access mode passed as the second argument to `FveOpenVolumeW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FveAccessMode {
    /// Query/status mode.
    ReadOnly = 0,
    /// Required for conversion operations.
    ReadWrite = 1,
}

/// Known FVE/Win32 HRESULT values returned by `fveapi.dll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FveError {
    Success,
    InvalidParameter,
    AccessDenied,
    VolumeLocked,
    NotSupported,
    NotEncrypted,
    KeyRequired,
    AuthenticationFailed,
    BadPassword,
    BadRecoveryPassword,
    VolumeUnlocked,
    NotBitLockerVolume,
    VolumeRemoved,
    NoMoreFiles,
    Other(u32),
}

impl FveError {
    /// Maps a raw HRESULT to a known error when possible.
    pub const fn from_hresult(code: u32) -> Self {
        match code {
            0x0000_0000 => Self::Success,
            0x8007_0057 => Self::InvalidParameter,
            0x8007_0005 => Self::AccessDenied,
            0x8031_0000 => Self::VolumeLocked,
            0x8031_0001 => Self::NotSupported,
            0x8031_0008 => Self::NotEncrypted,
            0x8031_0044 => Self::KeyRequired,
            0x8031_000D => Self::AuthenticationFailed,
            0x8031_0027 => Self::BadPassword,
            0x8031_0028 => Self::BadRecoveryPassword,
            0x8031_0023 => Self::VolumeUnlocked,
            0x8031_0049 => Self::NotBitLockerVolume,
            0x8031_004A => Self::VolumeRemoved,
            0x8007_0012 => Self::NoMoreFiles,
            other => Self::Other(other),
        }
    }

    /// Returns the raw HRESULT value.
    pub const fn code(self) -> u32 {
        match self {
            Self::Success => 0x0000_0000,
            Self::InvalidParameter => 0x8007_0057,
            Self::AccessDenied => 0x8007_0005,
            Self::VolumeLocked => 0x8031_0000,
            Self::NotSupported => 0x8031_0001,
            Self::NotEncrypted => 0x8031_0008,
            Self::KeyRequired => 0x8031_0044,
            Self::AuthenticationFailed => 0x8031_000D,
            Self::BadPassword => 0x8031_0027,
            Self::BadRecoveryPassword => 0x8031_0028,
            Self::VolumeUnlocked => 0x8031_0023,
            Self::NotBitLockerVolume => 0x8031_0049,
            Self::VolumeRemoved => 0x8031_004A,
            Self::NoMoreFiles => 0x8007_0012,
            Self::Other(code) => code,
        }
    }

    /// Returns true when this result means the volume is not BitLocker encrypted.
    pub const fn indicates_not_encrypted(self) -> bool {
        matches!(
            self,
            Self::NotEncrypted | Self::NotBitLockerVolume | Self::NotSupported
        )
    }

    /// Returns true when this result means an unlock/authentication path is needed.
    pub const fn indicates_locked(self) -> bool {
        matches!(
            self,
            Self::VolumeLocked | Self::KeyRequired | Self::AuthenticationFailed
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Success => "S_OK",
            Self::InvalidParameter => "E_INVALIDARG",
            Self::AccessDenied => "E_ACCESSDENIED",
            Self::VolumeLocked => "FVE_E_LOCKED_VOLUME",
            Self::NotSupported => "FVE_E_NOT_SUPPORTED",
            Self::NotEncrypted => "FVE_E_NOT_ENCRYPTED",
            Self::KeyRequired => "FVE_E_KEY_REQUIRED",
            Self::AuthenticationFailed => "FVE_E_FAILED_AUTHENTICATION",
            Self::BadPassword => "FVE_E_BAD_PASSWORD",
            Self::BadRecoveryPassword => "FVE_E_BAD_RECOVERY_PASSWORD",
            Self::VolumeUnlocked => "FVE_E_VOLUME_NOT_LOCKED",
            Self::NotBitLockerVolume => "FVE_E_NOT_BITLOCKER_VOLUME",
            Self::VolumeRemoved => "FVE_E_VOLUME_REMOVED",
            Self::NoMoreFiles => "HRESULT_FROM_WIN32(ERROR_NO_MORE_FILES)",
            Self::Other(_) => "unknown HRESULT",
        }
    }
}

impl fmt::Display for FveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08X})", self.name(), self.code())
    }
}

impl std::error::Error for FveError {}

/// Public crate-level error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FveApiError {
    UnsupportedPlatform,
    LibraryLoadFailed(String),
    MissingExport(&'static str),
    MemoryProtectionFailed(&'static str, String),
    Hresult(FveError),
}

impl fmt::Display for FveApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "fveapi.dll is only available on Windows"),
            Self::LibraryLoadFailed(message) => write!(f, "failed to load fveapi.dll: {message}"),
            Self::MissingExport(name) => write!(f, "fveapi.dll is missing export {name}"),
            Self::MemoryProtectionFailed(operation, message) => {
                write!(f, "{operation} failed: {message}")
            }
            Self::Hresult(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FveApiError {}

impl From<FveError> for FveApiError {
    fn from(value: FveError) -> Self {
        Self::Hresult(value)
    }
}

/// BitLocker conversion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FveVolumeStatus {
    FullyDecrypted,
    FullyEncrypted,
    EncryptionInProgress,
    DecryptionInProgress,
    EncryptionPaused,
    DecryptionPaused,
    Unknown(u16),
}

impl FveVolumeStatus {
    /// Converts the raw `wConversionStatus` value from status output.
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0 => Self::FullyDecrypted,
            1 => Self::FullyEncrypted,
            2 => Self::EncryptionInProgress,
            3 => Self::DecryptionInProgress,
            4 => Self::EncryptionPaused,
            5 => Self::DecryptionPaused,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw conversion status value.
    pub const fn raw(self) -> u16 {
        match self {
            Self::FullyDecrypted => 0,
            Self::FullyEncrypted => 1,
            Self::EncryptionInProgress => 2,
            Self::DecryptionInProgress => 3,
            Self::EncryptionPaused => 4,
            Self::DecryptionPaused => 5,
            Self::Unknown(value) => value,
        }
    }
}

/// Parsed `FveGetStatus` information.
#[derive(Debug, Clone, PartialEq)]
pub struct FveVolumeInfo {
    pub layout: FveStatusLayout,
    pub conversion_status: FveVolumeStatus,
    pub raw_conversion_status: u16,
    pub encryption_flags: u32,
    pub percent_complete: f64,
    pub encryption_percentage: u8,
    pub last_error: Option<u32>,
    pub volume_size: Option<u64>,
    pub wipe_percentage: Option<f64>,
    pub fvek_type: Option<u32>,
    pub encryption_method: Option<u32>,
    pub extended_flags: Option<u64>,
}

impl FveVolumeInfo {
    /// Parses a status buffer using the negotiated layout size as a guard.
    pub fn from_status_buffer(buffer: &FveStatusBuffer, layout: FveStatusLayout) -> Self {
        let raw_conversion_status = buffer
            .read_u16(layout, OFFSET_CONVERSION_STATUS)
            .unwrap_or_default();
        let percent_complete = buffer
            .read_f64(layout, OFFSET_PERCENT_COMPLETE)
            .unwrap_or_default()
            .clamp(0.0, 100.0);

        Self {
            layout,
            conversion_status: FveVolumeStatus::from_raw(raw_conversion_status),
            raw_conversion_status,
            encryption_flags: buffer
                .read_u32(layout, OFFSET_ENCRYPTION_FLAGS)
                .unwrap_or_default(),
            percent_complete,
            encryption_percentage: percent_complete.round() as u8,
            last_error: buffer.read_u32(layout, OFFSET_LAST_ERROR),
            volume_size: buffer.read_u64(layout, OFFSET_VOLUME_SIZE),
            wipe_percentage: buffer.read_f64(layout, OFFSET_WIPE_PERCENTAGE),
            fvek_type: buffer.read_u32(layout, OFFSET_FVEK_TYPE),
            encryption_method: buffer.read_u32(layout, OFFSET_ENCRYPTION_METHOD),
            extended_flags: buffer.read_u64(layout, OFFSET_EXTENDED_FLAGS),
        }
    }

    /// Best-effort encrypted-state check based on conversion status and flags.
    pub fn is_encrypted(&self) -> bool {
        (self.encryption_flags & FVE_FLAG_CHECK_MASK) != 0
            || matches!(
                self.conversion_status,
                FveVolumeStatus::FullyEncrypted
                    | FveVolumeStatus::EncryptionInProgress
                    | FveVolumeStatus::DecryptionInProgress
                    | FveVolumeStatus::EncryptionPaused
                    | FveVolumeStatus::DecryptionPaused
            )
    }
}

/// Authentication element kind used by `fveapi.dll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FveAuthElementKind {
    Passphrase,
    RecoveryPassword,
}

impl FveAuthElementKind {
    #[cfg(any(windows, test))]
    const fn buffer_size(self) -> usize {
        match self {
            Self::Passphrase => FVE_PASSPHRASE_AUTH_ELEMENT_SIZE,
            Self::RecoveryPassword => FVE_RECOVERY_AUTH_ELEMENT_SIZE,
        }
    }
}

#[cfg(any(windows, test))]
#[repr(C)]
struct FveAuthInformation {
    size: u32,
    version: u32,
    flags: u32,
    element_count: u32,
    elements: *mut *mut c_void,
    description: *mut u16,
    reserved0: u64,
    reserved1: u64,
    reserved2: u64,
}

#[cfg(any(windows, test))]
impl FveAuthInformation {
    fn new(elements: &mut [*mut c_void]) -> Self {
        Self {
            size: FVE_AUTH_INFORMATION_SIZE,
            version: FVE_AUTH_INFORMATION_VERSION,
            flags: 0,
            element_count: elements.len() as u32,
            elements: elements.as_mut_ptr(),
            description: std::ptr::null_mut(),
            reserved0: 0,
            reserved1: 0,
            reserved2: 0,
        }
    }
}

#[cfg(all(any(windows, test), target_pointer_width = "64"))]
const _: () =
    assert!(std::mem::size_of::<FveAuthInformation>() == FVE_AUTH_INFORMATION_SIZE as usize);

#[cfg(test)]
fn initialized_auth_element_buffer(kind: FveAuthElementKind) -> Vec<u8> {
    let size = kind.buffer_size();
    let mut buffer = vec![0u8; size];
    write_u32_at(&mut buffer, OFFSET_SIZE, size as u32);
    write_u32_at(&mut buffer, OFFSET_VERSION, FVE_AUTH_ELEMENT_VERSION);
    buffer
}

#[cfg(windows)]
mod windows_api {
    use super::*;

    type FnFveOpenVolumeW = unsafe extern "system" fn(*const u16, u32, *mut *mut c_void) -> u32;
    type FnFveCloseVolume = unsafe extern "system" fn(*mut c_void) -> u32;
    type FnFveGetStatusW = unsafe extern "system" fn(*const u16, *mut c_void) -> u32;
    type FnFveGetStatus = unsafe extern "system" fn(*mut c_void, *mut c_void) -> u32;
    type FnFveUnlockVolume =
        unsafe extern "system" fn(*mut c_void, *const FveAuthInformation) -> u32;
    type FnFveLockVolume = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    type FnFveConversionDecrypt = unsafe extern "system" fn(*mut c_void) -> u32;
    type FnFveConversionDecryptEx = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    type FnFveAuthElementFromPassPhraseW =
        unsafe extern "system" fn(*const u16, *mut c_void) -> u32;
    type FnFveAuthElementFromRecoveryPasswordW =
        unsafe extern "system" fn(*const u16, *mut c_void) -> u32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(lp_lib_file_name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn VirtualAlloc(
            lp_address: *mut c_void,
            dw_size: usize,
            fl_allocation_type: u32,
            fl_protect: u32,
        ) -> *mut c_void;
        fn VirtualFree(lp_address: *mut c_void, dw_size: usize, dw_free_type: u32) -> i32;
        fn VirtualLock(lp_address: *mut c_void, dw_size: usize) -> i32;
        fn VirtualUnlock(lp_address: *mut c_void, dw_size: usize) -> i32;
        fn VirtualProtect(
            lp_address: *mut c_void,
            dw_size: usize,
            fl_new_protect: u32,
            lpfl_old_protect: *mut u32,
        ) -> i32;
    }

    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const MEM_RELEASE: u32 = 0x0000_8000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READWRITE: u32 = 0x04;

    struct ProtectedAuthElement {
        ptr: *mut u8,
        len: usize,
        locked: bool,
        noaccess: bool,
    }

    impl ProtectedAuthElement {
        fn new(kind: FveAuthElementKind) -> Result<Self, FveApiError> {
            let len = kind.buffer_size();
            let ptr = unsafe {
                VirtualAlloc(
                    std::ptr::null_mut(),
                    len,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            }
            .cast::<u8>();

            if ptr.is_null() {
                return Err(FveApiError::MemoryProtectionFailed(
                    "VirtualAlloc",
                    std::io::Error::last_os_error().to_string(),
                ));
            }

            let locked = unsafe { VirtualLock(ptr.cast::<c_void>(), len) } != 0;
            let mut buffer = Self {
                ptr,
                len,
                locked,
                noaccess: false,
            };
            write_u32_at(buffer.as_mut_slice(), OFFSET_SIZE, len as u32);
            write_u32_at(
                buffer.as_mut_slice(),
                OFFSET_VERSION,
                FVE_AUTH_ELEMENT_VERSION,
            );
            Ok(buffer)
        }

        fn as_mut_ptr(&mut self) -> *mut c_void {
            self.ptr.cast::<c_void>()
        }

        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }

        fn zero_and_protect(&mut self) {
            if self.ptr.is_null() || self.noaccess {
                return;
            }

            secure_zero(self.ptr, self.len);

            if self.locked {
                unsafe {
                    VirtualUnlock(self.ptr.cast::<c_void>(), self.len);
                }
                self.locked = false;
            }

            let mut old_protect = 0u32;
            if unsafe {
                VirtualProtect(
                    self.ptr.cast::<c_void>(),
                    self.len,
                    PAGE_NOACCESS,
                    &mut old_protect,
                )
            } != 0
            {
                self.noaccess = true;
            }
        }
    }

    impl Drop for ProtectedAuthElement {
        fn drop(&mut self) {
            if self.ptr.is_null() {
                return;
            }

            self.zero_and_protect();
            unsafe {
                VirtualFree(self.ptr.cast::<c_void>(), 0, MEM_RELEASE);
            }
            self.ptr = std::ptr::null_mut();
            self.len = 0;
        }
    }

    fn secure_zero(ptr: *mut u8, len: usize) {
        for offset in 0..len {
            unsafe {
                std::ptr::write_volatile(ptr.add(offset), 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    pub(super) struct DynamicLibrary {
        module: *mut c_void,
    }

    unsafe impl Send for DynamicLibrary {}
    unsafe impl Sync for DynamicLibrary {}

    impl DynamicLibrary {
        fn load(name: &str) -> Result<Self, FveApiError> {
            let wide = to_wide_null(name);
            let module = unsafe { LoadLibraryW(wide.as_ptr()) };
            if module.is_null() {
                return Err(FveApiError::LibraryLoadFailed(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(Self { module })
        }

        unsafe fn symbol<T>(
            &self,
            display_name: &'static str,
            nul_name: &'static [u8],
        ) -> Result<T, FveApiError>
        where
            T: Copy,
        {
            debug_assert_eq!(nul_name.last(), Some(&0));
            debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());

            let raw = unsafe { GetProcAddress(self.module, nul_name.as_ptr()) };
            if raw.is_null() {
                return Err(FveApiError::MissingExport(display_name));
            }

            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&raw) })
        }
    }

    impl Drop for DynamicLibrary {
        fn drop(&mut self) {
            if !self.module.is_null() {
                unsafe {
                    FreeLibrary(self.module);
                }
            }
        }
    }

    pub struct FveApi {
        _library: DynamicLibrary,
        fn_open_volume: FnFveOpenVolumeW,
        fn_close_volume: FnFveCloseVolume,
        fn_get_status_w: FnFveGetStatusW,
        fn_get_status: FnFveGetStatus,
        fn_unlock_volume: FnFveUnlockVolume,
        fn_lock_volume: FnFveLockVolume,
        fn_conversion_decrypt: FnFveConversionDecrypt,
        fn_conversion_decrypt_ex: FnFveConversionDecryptEx,
        fn_auth_from_passphrase: FnFveAuthElementFromPassPhraseW,
        fn_auth_from_recovery: FnFveAuthElementFromRecoveryPasswordW,
    }

    unsafe impl Send for FveApi {}
    unsafe impl Sync for FveApi {}

    static FVE_API_INSTANCE: OnceLock<Result<FveApi, FveApiError>> = OnceLock::new();

    impl FveApi {
        /// Loads `fveapi.dll` and resolves all exports used by this crate.
        pub fn load() -> Result<Self, FveApiError> {
            let library = DynamicLibrary::load("fveapi.dll")?;

            let fn_open_volume = unsafe {
                library.symbol::<FnFveOpenVolumeW>("FveOpenVolumeW", b"FveOpenVolumeW\0")?
            };
            let fn_close_volume = unsafe {
                library.symbol::<FnFveCloseVolume>("FveCloseVolume", b"FveCloseVolume\0")?
            };
            let fn_get_status_w =
                unsafe { library.symbol::<FnFveGetStatusW>("FveGetStatusW", b"FveGetStatusW\0")? };
            let fn_get_status =
                unsafe { library.symbol::<FnFveGetStatus>("FveGetStatus", b"FveGetStatus\0")? };
            let fn_unlock_volume = unsafe {
                library.symbol::<FnFveUnlockVolume>("FveUnlockVolume", b"FveUnlockVolume\0")?
            };
            let fn_lock_volume =
                unsafe { library.symbol::<FnFveLockVolume>("FveLockVolume", b"FveLockVolume\0")? };
            let fn_conversion_decrypt = unsafe {
                library.symbol::<FnFveConversionDecrypt>(
                    "FveConversionDecrypt",
                    b"FveConversionDecrypt\0",
                )?
            };
            let fn_conversion_decrypt_ex = unsafe {
                library.symbol::<FnFveConversionDecryptEx>(
                    "FveConversionDecryptEx",
                    b"FveConversionDecryptEx\0",
                )?
            };
            let fn_auth_from_passphrase = unsafe {
                library.symbol::<FnFveAuthElementFromPassPhraseW>(
                    "FveAuthElementFromPassPhraseW",
                    b"FveAuthElementFromPassPhraseW\0",
                )?
            };
            let fn_auth_from_recovery = unsafe {
                library.symbol::<FnFveAuthElementFromRecoveryPasswordW>(
                    "FveAuthElementFromRecoveryPasswordW",
                    b"FveAuthElementFromRecoveryPasswordW\0",
                )?
            };

            Ok(Self {
                _library: library,
                fn_open_volume,
                fn_close_volume,
                fn_get_status_w,
                fn_get_status,
                fn_unlock_volume,
                fn_lock_volume,
                fn_conversion_decrypt,
                fn_conversion_decrypt_ex,
                fn_auth_from_passphrase,
                fn_auth_from_recovery,
            })
        }

        /// Returns a process-wide `FveApi` instance.
        pub fn instance() -> Result<&'static Self, FveApiError> {
            match FVE_API_INSTANCE.get_or_init(Self::load) {
                Ok(api) => Ok(api),
                Err(error) => Err(error.clone()),
            }
        }

        /// Probes the first status layout accepted by this Windows build.
        pub fn probe_status_layout(
            &self,
            volume_path: &str,
        ) -> Result<FveStatusProbe, FveApiError> {
            let normalized_path = normalize_volume_path(volume_path);
            let wide_path = to_wide_null(&normalized_path);

            for layout in FVE_STATUS_LAYOUTS {
                let mut status_buffer = FveStatusBuffer::new(layout);
                let hresult = unsafe {
                    (self.fn_get_status_w)(wide_path.as_ptr(), status_buffer.as_mut_ptr())
                };

                if hresult != FveError::InvalidParameter.code() {
                    let status = (hresult == FveError::Success.code())
                        .then(|| FveVolumeInfo::from_status_buffer(&status_buffer, layout));
                    return Ok(FveStatusProbe {
                        layout,
                        hresult,
                        status,
                    });
                }
            }

            Err(FveError::InvalidParameter.into())
        }

        /// Gets BitLocker status by drive path (`C:`, `C:\`, `\\.\C:`, or volume GUID).
        pub fn get_status_by_path(&self, volume_path: &str) -> Result<FveVolumeInfo, FveApiError> {
            let normalized_path = normalize_volume_path(volume_path);
            let wide_path = to_wide_null(&normalized_path);

            for layout in FVE_STATUS_LAYOUTS {
                let mut status_buffer = FveStatusBuffer::new(layout);
                let hresult = unsafe {
                    (self.fn_get_status_w)(wide_path.as_ptr(), status_buffer.as_mut_ptr())
                };

                if hresult == FveError::Success.code() {
                    return Ok(FveVolumeInfo::from_status_buffer(&status_buffer, layout));
                }
                if hresult != FveError::InvalidParameter.code() {
                    return Err(FveError::from_hresult(hresult).into());
                }
            }

            Err(FveError::InvalidParameter.into())
        }

        /// Opens a volume in read-only mode.
        pub fn open_volume(&self, volume_path: &str) -> Result<FveVolumeHandle<'_>, FveApiError> {
            self.open_volume_ex(volume_path, FveAccessMode::ReadOnly)
        }

        /// Opens a volume with the requested FVE access mode.
        pub fn open_volume_ex(
            &self,
            volume_path: &str,
            access_mode: FveAccessMode,
        ) -> Result<FveVolumeHandle<'_>, FveApiError> {
            let normalized_path = normalize_volume_path(volume_path);
            let wide_path = to_wide_null(&normalized_path);
            let mut handle = std::ptr::null_mut();
            let hresult = unsafe {
                (self.fn_open_volume)(wide_path.as_ptr(), access_mode as u32, &mut handle)
            };

            if hresult == FveError::Success.code() && !handle.is_null() {
                Ok(FveVolumeHandle { handle, api: self })
            } else {
                Err(FveError::from_hresult(hresult).into())
            }
        }

        fn create_auth_element(
            &self,
            kind: FveAuthElementKind,
            secret: &str,
        ) -> Result<ProtectedAuthElement, FveApiError> {
            let wide_secret = to_wide_null(secret);
            let mut auth_element = ProtectedAuthElement::new(kind)?;

            let hresult = match kind {
                FveAuthElementKind::Passphrase => unsafe {
                    (self.fn_auth_from_passphrase)(wide_secret.as_ptr(), auth_element.as_mut_ptr())
                },
                FveAuthElementKind::RecoveryPassword => unsafe {
                    (self.fn_auth_from_recovery)(wide_secret.as_ptr(), auth_element.as_mut_ptr())
                },
            };

            if hresult == FveError::Success.code() {
                Ok(auth_element)
            } else {
                auth_element.zero_and_protect();
                Err(FveError::from_hresult(hresult).into())
            }
        }
    }

    /// RAII FVE volume handle.
    pub struct FveVolumeHandle<'api> {
        handle: *mut c_void,
        api: &'api FveApi,
    }

    impl<'api> FveVolumeHandle<'api> {
        /// Gets status through an opened FVE volume handle.
        pub fn get_status(&self) -> Result<FveVolumeInfo, FveApiError> {
            for layout in FVE_STATUS_LAYOUTS {
                let mut status_buffer = FveStatusBuffer::new(layout);
                let hresult =
                    unsafe { (self.api.fn_get_status)(self.handle, status_buffer.as_mut_ptr()) };

                if hresult == FveError::Success.code() {
                    return Ok(FveVolumeInfo::from_status_buffer(&status_buffer, layout));
                }
                if hresult != FveError::InvalidParameter.code() {
                    return Err(FveError::from_hresult(hresult).into());
                }
            }

            Err(FveError::InvalidParameter.into())
        }

        /// Unlocks the volume with a passphrase.
        pub fn unlock_with_password(&self, password: &str) -> Result<(), FveApiError> {
            let auth_element = self
                .api
                .create_auth_element(FveAuthElementKind::Passphrase, password)?;
            self.unlock_with_auth_element(auth_element)
        }

        /// Unlocks the volume with a 48-digit BitLocker recovery password.
        pub fn unlock_with_recovery_key(&self, recovery_key: &str) -> Result<(), FveApiError> {
            let formatted = format_recovery_key(recovery_key)
                .map_err(|_| FveApiError::Hresult(FveError::InvalidParameter))?;
            let auth_element = self
                .api
                .create_auth_element(FveAuthElementKind::RecoveryPassword, &formatted)?;
            self.unlock_with_auth_element(auth_element)
        }

        fn unlock_with_auth_element(
            &self,
            mut auth_element: ProtectedAuthElement,
        ) -> Result<(), FveApiError> {
            let mut element_ptrs = [auth_element.as_mut_ptr()];
            let auth_info = FveAuthInformation::new(&mut element_ptrs);
            let hresult = unsafe { (self.api.fn_unlock_volume)(self.handle, &auth_info) };
            auth_element.zero_and_protect();

            if hresult == FveError::Success.code() || hresult == FveError::VolumeUnlocked.code() {
                Ok(())
            } else {
                Err(FveError::from_hresult(hresult).into())
            }
        }

        /// Locks the volume.
        pub fn lock(&self, dismount_first: bool) -> Result<(), FveApiError> {
            let hresult =
                unsafe { (self.api.fn_lock_volume)(self.handle, u32::from(dismount_first)) };
            if hresult == FveError::Success.code() {
                Ok(())
            } else {
                Err(FveError::from_hresult(hresult).into())
            }
        }

        /// Starts BitLocker decryption.
        pub fn start_decryption(&self) -> Result<(), FveApiError> {
            let hresult = unsafe { (self.api.fn_conversion_decrypt)(self.handle) };
            if hresult == FveError::Success.code() {
                Ok(())
            } else {
                Err(FveError::from_hresult(hresult).into())
            }
        }

        /// Starts BitLocker decryption with flags.
        pub fn start_decryption_ex(&self, flags: u32) -> Result<(), FveApiError> {
            let hresult = unsafe { (self.api.fn_conversion_decrypt_ex)(self.handle, flags) };
            if hresult == FveError::Success.code() {
                Ok(())
            } else {
                Err(FveError::from_hresult(hresult).into())
            }
        }

        /// Returns the raw FVE handle.
        pub fn as_raw(&self) -> *mut c_void {
            self.handle
        }
    }

    impl Drop for FveVolumeHandle<'_> {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    (self.api.fn_close_volume)(self.handle);
                }
            }
        }
    }
}

#[cfg(windows)]
pub use windows_api::{FveApi, FveVolumeHandle};

#[cfg(not(windows))]
mod non_windows_api {
    use super::*;
    use std::marker::PhantomData;

    pub struct FveApi;

    impl FveApi {
        pub fn load() -> Result<Self, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn instance() -> Result<&'static Self, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn probe_status_layout(
            &self,
            _volume_path: &str,
        ) -> Result<FveStatusProbe, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn get_status_by_path(&self, _volume_path: &str) -> Result<FveVolumeInfo, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn open_volume(&self, _volume_path: &str) -> Result<FveVolumeHandle<'_>, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn open_volume_ex(
            &self,
            _volume_path: &str,
            _access_mode: FveAccessMode,
        ) -> Result<FveVolumeHandle<'_>, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }
    }

    pub struct FveVolumeHandle<'api> {
        _marker: PhantomData<&'api ()>,
    }

    impl FveVolumeHandle<'_> {
        pub fn get_status(&self) -> Result<FveVolumeInfo, FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn unlock_with_password(&self, _password: &str) -> Result<(), FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn unlock_with_recovery_key(&self, _recovery_key: &str) -> Result<(), FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn lock(&self, _dismount_first: bool) -> Result<(), FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn start_decryption(&self) -> Result<(), FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn start_decryption_ex(&self, _flags: u32) -> Result<(), FveApiError> {
            Err(FveApiError::UnsupportedPlatform)
        }

        pub fn as_raw(&self) -> *mut c_void {
            std::ptr::null_mut()
        }
    }
}

#[cfg(not(windows))]
pub use non_windows_api::{FveApi, FveVolumeHandle};

/// Formats a BitLocker recovery password as 8 groups of 6 digits.
pub fn format_recovery_key(input: &str) -> Result<String, String> {
    let digits: String = input.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.len() != 48 {
        return Err(format!(
            "recovery key must contain exactly 48 digits, got {}",
            digits.len()
        ));
    }

    let mut formatted = String::with_capacity(55);
    for index in 0..8 {
        if index > 0 {
            formatted.push('-');
        }
        let start = index * 6;
        formatted.push_str(&digits[start..start + 6]);
    }
    Ok(formatted)
}

/// Normalizes common drive paths into the form expected by `FveGetStatusW`.
pub fn normalize_volume_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.contains("Volume{") {
        return trimmed.to_string();
    }

    if let Some(rest) = trimmed
        .strip_prefix("\\\\.\\")
        .or_else(|| trimmed.strip_prefix("\\\\?\\"))
    {
        if let Some(drive) = normalize_drive(rest) {
            return drive;
        }
    }

    normalize_drive(trimmed).unwrap_or_else(|| trimmed.to_string())
}

fn normalize_drive(value: &str) -> Option<String> {
    let mut chars = value.chars();
    let letter = chars.next()?;
    let colon = chars.next()?;

    (letter.is_ascii_alphabetic() && colon == ':')
        .then(|| format!("{}:", letter.to_ascii_uppercase()))
}

#[cfg(windows)]
fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    let mut raw = [0; 2];
    raw.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(raw)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(raw)
}

fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_layout_table_matches_verified_versions() {
        assert_eq!(FVE_STATUS_LAYOUTS[0], FveStatusLayout::new(9, 0x80));
        assert!(FVE_STATUS_LAYOUTS.contains(&FveStatusLayout::new(8, 0x78)));
        assert!(FVE_STATUS_LAYOUTS.contains(&FveStatusLayout::new(5, 0x58)));
        assert!(FVE_STATUS_LAYOUTS.contains(&FveStatusLayout::new(1, 0x20)));

        for pair in FVE_STATUS_LAYOUTS.windows(2) {
            assert!(pair[0].version > pair[1].version);
        }
    }

    #[test]
    fn status_buffer_has_expected_size_alignment_and_header() {
        assert_eq!(std::mem::size_of::<FveStatusBuffer>(), MAX_STATUS_SIZE);
        assert_eq!(std::mem::align_of::<FveStatusBuffer>(), 8);

        let buffer = FveStatusBuffer::new(FveStatusLayout::new(9, 0x80));
        assert_eq!(read_u32_at(buffer.bytes(), OFFSET_SIZE), 0x80);
        assert_eq!(read_u32_at(buffer.bytes(), OFFSET_VERSION), 9);
    }

    #[test]
    fn parses_v9_status_offsets() {
        let layout = FveStatusLayout::new(9, 0x80);
        let mut buffer = FveStatusBuffer::new(layout);
        write_u16_at(&mut buffer.bytes, OFFSET_CONVERSION_STATUS, 3);
        write_u32_at(&mut buffer.bytes, OFFSET_ENCRYPTION_FLAGS, 0x17F);
        write_u64_at(
            &mut buffer.bytes,
            OFFSET_PERCENT_COMPLETE,
            42.4f64.to_bits(),
        );
        write_u32_at(&mut buffer.bytes, OFFSET_LAST_ERROR, 0x1234);
        write_u64_at(&mut buffer.bytes, OFFSET_VOLUME_SIZE, 0x1000_0000);
        write_u64_at(&mut buffer.bytes, OFFSET_WIPE_PERCENTAGE, 7.0f64.to_bits());
        write_u32_at(&mut buffer.bytes, OFFSET_FVEK_TYPE, 2);
        write_u32_at(&mut buffer.bytes, OFFSET_ENCRYPTION_METHOD, 7);
        write_u64_at(&mut buffer.bytes, OFFSET_EXTENDED_FLAGS, 0xABCD);

        let info = FveVolumeInfo::from_status_buffer(&buffer, layout);
        assert_eq!(
            info.conversion_status,
            FveVolumeStatus::DecryptionInProgress
        );
        assert_eq!(info.raw_conversion_status, 3);
        assert_eq!(info.encryption_flags, 0x17F);
        assert_eq!(info.encryption_percentage, 42);
        assert_eq!(info.last_error, Some(0x1234));
        assert_eq!(info.volume_size, Some(0x1000_0000));
        assert_eq!(info.wipe_percentage, Some(7.0));
        assert_eq!(info.fvek_type, Some(2));
        assert_eq!(info.encryption_method, Some(7));
        assert_eq!(info.extended_flags, Some(0xABCD));
        assert!(info.is_encrypted());
    }

    #[test]
    fn parsing_respects_negotiated_size_guard() {
        let layout = FveStatusLayout::new(2, 0x20);
        let mut buffer = FveStatusBuffer::new(layout);
        write_u16_at(&mut buffer.bytes, OFFSET_CONVERSION_STATUS, 1);
        write_u32_at(&mut buffer.bytes, OFFSET_ENCRYPTION_FLAGS, 0x10);
        write_u64_at(
            &mut buffer.bytes,
            OFFSET_PERCENT_COMPLETE,
            99.9f64.to_bits(),
        );
        write_u64_at(&mut buffer.bytes, OFFSET_VOLUME_SIZE, 0xDEAD_BEEF);
        write_u64_at(&mut buffer.bytes, OFFSET_EXTENDED_FLAGS, 0xBAD);

        let info = FveVolumeInfo::from_status_buffer(&buffer, layout);
        assert_eq!(info.conversion_status, FveVolumeStatus::FullyEncrypted);
        assert_eq!(info.encryption_percentage, 100);
        assert_eq!(info.volume_size, None);
        assert_eq!(info.extended_flags, None);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn auth_information_layout_matches_ida() {
        assert_eq!(
            std::mem::size_of::<FveAuthInformation>(),
            FVE_AUTH_INFORMATION_SIZE as usize
        );
        assert_eq!(std::mem::align_of::<FveAuthInformation>(), 8);

        let mut elements = [std::ptr::null_mut()];
        let auth_info = FveAuthInformation::new(&mut elements);
        assert_eq!(auth_info.size, 0x38);
        assert_eq!(auth_info.version, 1);
        assert_eq!(auth_info.element_count, 1);
        assert!(!auth_info.elements.is_null());
    }

    #[test]
    fn auth_element_buffers_have_required_headers() {
        let passphrase = initialized_auth_element_buffer(FveAuthElementKind::Passphrase);
        assert_eq!(passphrase.len(), 0x248);
        assert_eq!(read_u32_at(&passphrase, OFFSET_SIZE), 0x248);
        assert_eq!(read_u32_at(&passphrase, OFFSET_VERSION), 1);

        let recovery = initialized_auth_element_buffer(FveAuthElementKind::RecoveryPassword);
        assert_eq!(recovery.len(), 0x20);
        assert_eq!(read_u32_at(&recovery, OFFSET_SIZE), 0x20);
        assert_eq!(read_u32_at(&recovery, OFFSET_VERSION), 1);
    }

    #[test]
    fn formats_recovery_key() {
        let key = "123456789012345678901234567890123456789012345678";
        assert_eq!(
            format_recovery_key(key).unwrap(),
            "123456-789012-345678-901234-567890-123456-789012-345678"
        );

        let dashed = "123456-789012-345678-901234-567890-123456-789012-345678";
        assert_eq!(format_recovery_key(dashed).unwrap(), dashed);
        assert!(format_recovery_key("12345").is_err());
    }

    #[test]
    fn normalizes_volume_paths() {
        assert_eq!(normalize_volume_path("C:"), "C:");
        assert_eq!(normalize_volume_path("c:"), "C:");
        assert_eq!(normalize_volume_path("C:\\"), "C:");
        assert_eq!(normalize_volume_path("D:\\Windows"), "D:");
        assert_eq!(normalize_volume_path("\\\\.\\e:"), "E:");
        assert_eq!(normalize_volume_path("\\\\?\\f:"), "F:");
        assert_eq!(
            normalize_volume_path("\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"),
            "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"
        );
    }

    #[test]
    fn maps_known_hresult_values() {
        assert_eq!(
            FveError::from_hresult(0x8007_0057),
            FveError::InvalidParameter
        );
        assert_eq!(FveError::VolumeLocked.code(), 0x8031_0000);
        assert!(FveError::NotEncrypted.indicates_not_encrypted());
        assert!(FveError::KeyRequired.indicates_locked());
        assert_eq!(
            FveError::from_hresult(0xDEAD_BEEF),
            FveError::Other(0xDEAD_BEEF)
        );
    }
}
