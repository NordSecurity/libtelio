use anyhow::Result;
use protobuf_codegen::Codegen;
use std::{
    env,
    fs::create_dir,
    io::{Error, ErrorKind},
    path::Path,
};

fn main() -> Result<()> {
    let out_dir = format!(
        "{}/protos",
        env::var("OUT_DIR").map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?
    );
    create_dir(Path::new(&out_dir)).or_else(|err| match err.kind() {
        ErrorKind::AlreadyExists => Ok(()),
        _ => Err(err),
    })?;
    Codegen::new()
        .pure()
        .include("protos")
        .inputs([
            "protos/nurse.proto",
            "protos/natter.proto",
            "protos/pinger.proto",
            "protos/upgrade.proto",
            "protos/derppoll.proto",
        ])
        .out_dir(out_dir)
        .run()?;

    let mut config = tonic_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional"); // This is needed for older protoc versions
    tonic_build::configure().compile_protos_with_config(
        config,
        &["protos/ens.proto"],
        &["protos"],
    )?;

    Ok(())
}
