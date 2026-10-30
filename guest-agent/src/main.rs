use std::process::ExitCode;

fn main() -> ExitCode
{
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) =>
        {
            eprintln!("quarry-guest-agent: cannot start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(guest_agent::run());
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
