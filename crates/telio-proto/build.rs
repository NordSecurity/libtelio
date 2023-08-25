use protobuf_codegen_pure::{Codegen, Customize};
use std::{
    env,
    fs::create_dir,
    io::{Error, ErrorKind, Result},
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
        .customize(Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .include("protos")
        .inputs([
            "protos/nurse.proto",
            "protos/natter.proto",
            "protos/pinger.proto",
            "protos/upgrade.proto",
            "protos/derppoll.proto",
        ])
        .out_dir(out_dir)
        .run()
}
