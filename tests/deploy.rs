//! Guards for the shipped deployment artifacts.
//!
//! A unit file is not executable code, so nothing else in the suite notices when
//! it silently stops matching the binary. These tests pin the two properties that
//! were actually broken: the filesystem sandbox must not forbid the filesystems
//! the database lives on, and the unit must not advertise a reload the process
//! cannot honour.

use std::path::PathBuf;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn systemd_unit_keeps_a_supported_filesystem_sandbox() {
    let unit = read("deploy/redis-honeypot-rs.service");

    let restrict = unit
        .lines()
        .find(|line| line.trim_start().starts_with("RestrictFileSystems="))
        .expect("RestrictFileSystems must stay declared");
    // `@basic-api` alone blocks ext4/xfs/btrfs, so SQLite could not create its
    // file. The block filesystem group has to be part of the whitelist.
    assert!(
        restrict.contains("@common-block"),
        "RestrictFileSystems must allow common block filesystems: {restrict}"
    );

    // The hardening that must not be lost while fixing the above.
    for required in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "CapabilityBoundingSet=",
        "SystemCallFilter=@system-service",
        "MemoryMax=",
        "CPUQuota=",
        "RestrictAddressFamilies=AF_INET AF_INET6",
    ] {
        assert!(
            unit.contains(required),
            "the unit lost a hardening option: {required}"
        );
    }

    // SIGTERM must stay the stop signal: it is what triggers the graceful drain.
    assert!(unit.contains("KillSignal=SIGTERM"));
    assert!(unit.contains("Restart="), "the unit must be restartable");
    assert!(
        unit.contains("StartLimitBurst=") && unit.contains("StartLimitIntervalSec="),
        "a restart loop must be bounded"
    );
}

/// `ExecReload` is only allowed to exist because the process really handles
/// SIGHUP: the unit and the binary must not drift apart again.
#[test]
fn systemd_unit_reload_matches_an_implemented_signal_handler() {
    let unit = read("deploy/redis-honeypot-rs.service");
    let exec_reload: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.starts_with("ExecReload="))
        .collect();
    assert_eq!(
        exec_reload.len(),
        1,
        "the unit must declare exactly one reload command"
    );
    assert!(
        exec_reload[0].contains("-HUP") && exec_reload[0].contains("$MAINPID"),
        "reload must be a SIGHUP: {}",
        exec_reload[0]
    );

    // The claim is verified against the code, not assumed: the binary has to
    // subscribe to SIGHUP and re-resolve the configuration when it fires.
    let main = read("src/main.rs");
    assert!(
        main.contains("SignalKind::hangup()"),
        "ExecReload advertises SIGHUP but main.rs never subscribes to it"
    );
    assert!(
        main.contains("resolve_config()"),
        "the reload path must re-resolve the configuration"
    );
    assert!(
        main.contains("keeping the running configuration"),
        "an invalid reload must be reported, not fatal"
    );
    // The unit has to say what a reload does *not* cover.
    assert!(
        unit.contains("systemctl restart"),
        "the unit should tell the operator what still needs a restart"
    );
    assert!(
        unit.contains("Fixed at startup"),
        "the unit must name the restart-only settings"
    );
}

#[test]
fn example_config_covers_every_virtual_store_cap() {
    let example = read("deploy/config.example.toml");
    for key in [
        "store_max_keys",
        "store_max_bytes",
        "store_max_value_bytes",
        "store_max_collection_len",
        "max_stored_param_bytes",
    ] {
        assert!(
            example.contains(key),
            "config.example.toml does not document {key}"
        );
    }
    // The shipped example must parse and validate with the real loader.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/config.example.toml");
    redis_honeypot_rs::config::Config::load_toml(&path).expect("the example config must be valid");
}
