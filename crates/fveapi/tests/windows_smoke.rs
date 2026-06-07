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

#[cfg(not(windows))]
#[test]
fn reports_unsupported_platform() {
    match FveApi::load() {
        Err(FveApiError::UnsupportedPlatform) => {}
        Ok(_) => panic!("non-Windows hosts must not load fveapi.dll"),
        Err(other) => panic!("unexpected error on non-Windows: {other}"),
    }
}
