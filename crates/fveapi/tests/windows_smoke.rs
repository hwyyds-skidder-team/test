#[cfg(windows)]
use fveapi::{FveApi, FveError, FVE_STATUS_LAYOUTS};

#[cfg(not(windows))]
use fveapi::{FveApi, FveApiError};

#[cfg(windows)]
#[test]
fn loads_fveapi_exports() {
    FveApi::load().expect("fveapi.dll should load and expose the verified symbols");
}

#[cfg(windows)]
#[test]
fn probes_status_layout_for_system_drive() {
    let api = FveApi::load().expect("fveapi.dll should load");
    let probe = api
        .probe_status_layout("C:")
        .expect("at least one FveGetStatus layout should be accepted for C:");

    assert!(
        FVE_STATUS_LAYOUTS.contains(&probe.layout),
        "unexpected accepted status layout: {:?}",
        probe.layout
    );

    if probe.hresult != FveError::Success.code() {
        let error = FveError::from_hresult(probe.hresult);
        assert_ne!(
            error,
            FveError::InvalidParameter,
            "probe must skip layouts rejected by E_INVALIDARG"
        );
    }
}

#[cfg(windows)]
#[test]
fn tries_lock_on_all_logical_drives() {
    let api = FveApi::load().expect("fveapi.dll should load");
    let drives = logical_drive_letters();
    assert!(
        !drives.is_empty(),
        "Windows should report at least one drive"
    );

    let mut lock_attempts = 0usize;
    for letter in drives {
        let volume = format!("{letter}:");
        println!("=== testing {volume} ===");

        match api.probe_status_layout(&volume) {
            Ok(probe) => {
                println!(
                    "{volume}: status layout v{} size=0x{:X}, hr=0x{:08X}",
                    probe.layout.version, probe.layout.size, probe.hresult
                );
                if let Some(status) = probe.status {
                    println!(
                        "{volume}: status={:?}, encrypted={}, flags=0x{:08X}, percent={}",
                        status.conversion_status,
                        status.is_encrypted(),
                        status.encryption_flags,
                        status.percent_complete
                    );
                }
            }
            Err(error) => {
                println!("{volume}: status probe failed: {error}");
            }
        }

        match api.open_volume(&volume) {
            Ok(handle) => {
                lock_attempts += 1;
                match handle.get_status() {
                    Ok(status) => {
                        println!(
                            "{volume}: handle status={:?}, encrypted={}, flags=0x{:08X}, percent={}",
                            status.conversion_status,
                            status.is_encrypted(),
                            status.encryption_flags,
                            status.percent_complete
                        );
                    }
                    Err(error) => {
                        println!("{volume}: handle get_status failed: {error}");
                    }
                }

                match handle.lock(false) {
                    Ok(()) => {
                        println!("{volume}: FveLockVolume(false) succeeded");
                    }
                    Err(error) => {
                        println!("{volume}: FveLockVolume(false) failed: {error}");
                    }
                }
            }
            Err(error) => {
                println!("{volume}: FveOpenVolumeW failed: {error}");
            }
        }
    }

    println!("FveLockVolume(false) attempted on {lock_attempts} opened drive(s)");
}

#[cfg(windows)]
fn logical_drive_letters() -> Vec<char> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLogicalDrives() -> u32;
    }

    let mask = unsafe { GetLogicalDrives() };
    (0..26)
        .filter(|index| (mask & (1u32 << index)) != 0)
        .map(|index| char::from(b'A' + index as u8))
        .collect()
}

#[cfg(not(windows))]
#[test]
fn reports_unsupported_platform() {
    match FveApi::load() {
        Err(FveApiError::UnsupportedPlatform) => {}
        Ok(_) => panic!("non-Windows hosts must not load fveapi.dll"),
        Err(other) => panic!("unexpected error on non-Windows: {other}"),
    }
}
