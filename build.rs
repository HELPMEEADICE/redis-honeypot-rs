//! Build script.
//!
//! One job only: on mips*-linux-gnu, compile a tiny C shim that provides
//! `getrandom(2)`, which that libc predates. Every other target compiles
//! nothing extra.

fn main() {
    println!("cargo:rerun-if-changed=src/shim/getrandom_mips.c");
    println!("cargo:rerun-if-env-changed=TARGET");

    let target = std::env::var("TARGET").unwrap_or_default();
    let needs_shim = target.starts_with("mips-unknown-linux-gnu")
        || target.starts_with("mipsel-unknown-linux-gnu")
        || target.starts_with("mips64-unknown-linux-gnuabi64")
        || target.starts_with("mips64el-unknown-linux-gnuabi64");

    if needs_shim {
        // `cc` honours the CC_<target> / TARGET_CC variables that `cross` sets,
        // so the shim is compiled by the mips cross compiler, not the host one.
        cc::Build::new()
            .file("src/shim/getrandom_mips.c")
            .warnings(false)
            .compile("getrandom_mips_shim");
    }
}
