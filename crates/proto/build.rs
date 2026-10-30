use std::error::Error;

fn main() -> Result<(), Box<dyn Error>>
{
    println!("cargo:rerun-if-changed=proto");
    let descriptors = protox::compile(["quarry/agent/v1/agent.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .compile_fds(descriptors)?;
    Ok(())
}
