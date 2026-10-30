use crate::{Configure, GuestBody, GuestMessage, Health, HostBody, HostMessage};
use prost::Message;

/// Largest accepted [`crate::Ready::server_version`], in bytes.
pub const MAX_SERVER_VERSION_BYTES: usize = 128;
/// Largest accepted [`crate::Log::line`], in bytes.
pub const MAX_LOG_LINE_BYTES: usize = 4096;
/// Largest accepted [`crate::SnapshotPrepared::error`], in bytes.
pub const MAX_ERROR_BYTES: usize = 1024;
/// Largest accepted [`crate::Health::tps`].
pub const MAX_TPS: f64 = 1000.0;
/// Largest accepted [`crate::Health::mspt`].
pub const MAX_MSPT: f64 = 60_000.0;
/// Largest accepted [`crate::Health::players`].
pub const MAX_PLAYERS: u32 = 100_000;
/// Largest accepted [`crate::Health::heap_used_bytes`] (1 TiB).
pub const MAX_HEAP_BYTES: u64 = 1 << 40;
/// Largest accepted [`crate::ConsoleCommand::command`], in bytes.
pub const MAX_CONSOLE_COMMAND_BYTES: usize = 1024;
/// Largest accepted [`crate::Configure::instance_id`], in bytes.
pub const MAX_INSTANCE_ID_BYTES: usize = 128;
/// Largest accepted environment variable name, in bytes.
pub const MAX_ENV_NAME_BYTES: usize = 256;
/// Largest accepted environment variable value, in bytes.
pub const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;
/// Largest accepted secret file name, in bytes.
pub const MAX_SECRET_NAME_BYTES: usize = 255;
/// Largest accepted number of [`crate::Configure::server_command`] elements.
pub const MAX_COMMAND_ARGS: usize = 256;
/// Largest accepted [`crate::Configure::server_command`] element, in bytes.
pub const MAX_COMMAND_ARG_BYTES: usize = 4096;
/// Largest accepted [`crate::Shutdown::deadline_ms`] (one hour).
pub const MAX_SHUTDOWN_DEADLINE_MS: u64 = 3_600_000;

/// Error decoding or validating a guest channel message or transport string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestProtoError
{
    /// The bytes are not a valid protobuf encoding of the message.
    #[error("malformed message: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The message has no body.
    #[error("message has no body")]
    MissingBody,
    /// A numeric field is non-finite or outside its allowed range.
    #[error("field `{field}` is out of range")]
    OutOfRange
    {
        /// Offending field.
        field: &'static str,
    },
    /// A string or bytes field exceeds its length limit.
    #[error("field `{field}` exceeds {max} bytes")]
    TooLong
    {
        /// Offending field.
        field: &'static str,
        /// Limit in bytes.
        max: usize,
    },
    /// A field contains a character that is not allowed.
    #[error("field `{field}` contains a forbidden character")]
    ForbiddenCharacter
    {
        /// Offending field.
        field: &'static str,
    },
    /// A required field is empty or a name is not acceptable.
    #[error("field `{field}` is empty or invalid")]
    Invalid
    {
        /// Offending field.
        field: &'static str,
    },
    /// A transport string is not `vsock:<port>` or `unix:<absolute path>`.
    #[error("invalid transport `{0}`")]
    InvalidTransport(String),
}

/// Decodes and schema-validates a message received from the untrusted guest.
pub fn decode_guest_message(bytes: &[u8]) -> Result<GuestMessage, GuestProtoError>
{
    let message = GuestMessage::decode(bytes)?;
    match &message.body
    {
        None => return Err(GuestProtoError::MissingBody),
        Some(GuestBody::Ready(ready)) => single_line(
            "server_version",
            &ready.server_version,
            MAX_SERVER_VERSION_BYTES,
        )?,
        Some(GuestBody::Health(health)) => validate_health(health)?,
        Some(GuestBody::Log(log)) => single_line("line", &log.line, MAX_LOG_LINE_BYTES)?,
        Some(GuestBody::ShutdownComplete(_)) =>
        {}
        Some(GuestBody::SnapshotPrepared(prepared)) =>
        {
            single_line("error", &prepared.error, MAX_ERROR_BYTES)?
        }
    }
    Ok(message)
}

/// Decodes and validates a message received from the host.
pub fn decode_host_message(bytes: &[u8]) -> Result<HostMessage, GuestProtoError>
{
    let message = HostMessage::decode(bytes)?;
    match &message.body
    {
        None => return Err(GuestProtoError::MissingBody),
        Some(HostBody::Configure(configure)) => validate_configure(configure)?,
        Some(HostBody::ConsoleCommand(console)) =>
        {
            single_line("command", &console.command, MAX_CONSOLE_COMMAND_BYTES)?
        }
        Some(HostBody::PrepareSnapshot(_)) | Some(HostBody::ResumeWrites(_)) =>
        {}
        Some(HostBody::Shutdown(shutdown)) =>
        {
            if shutdown.deadline_ms > MAX_SHUTDOWN_DEADLINE_MS
            {
                return Err(GuestProtoError::OutOfRange {
                    field: "deadline_ms",
                });
            }
        }
    }
    Ok(message)
}

fn validate_health(health: &Health) -> Result<(), GuestProtoError>
{
    in_range("tps", health.tps, MAX_TPS)?;
    in_range("mspt", health.mspt, MAX_MSPT)?;
    if health.players > MAX_PLAYERS
    {
        return Err(GuestProtoError::OutOfRange { field: "players" });
    }
    if health.heap_used_bytes > MAX_HEAP_BYTES
    {
        return Err(GuestProtoError::OutOfRange {
            field: "heap_used_bytes",
        });
    }
    Ok(())
}

fn validate_configure(configure: &Configure) -> Result<(), GuestProtoError>
{
    single_line("instance_id", &configure.instance_id, MAX_INSTANCE_ID_BYTES)?;
    if configure.instance_id.is_empty()
    {
        return Err(GuestProtoError::Invalid {
            field: "instance_id",
        });
    }
    if configure.memory_mib == 0
    {
        return Err(GuestProtoError::OutOfRange {
            field: "memory_mib",
        });
    }
    for (name, value) in &configure.env
    {
        single_line("env", name, MAX_ENV_NAME_BYTES)?;
        if name.is_empty() || name.contains('=')
        {
            return Err(GuestProtoError::Invalid { field: "env" });
        }
        no_nul("env", value, MAX_ENV_VALUE_BYTES)?;
    }
    for name in configure.secrets.keys()
    {
        single_line("secrets", name, MAX_SECRET_NAME_BYTES)?;
        if name.is_empty() || name == "." || name == ".." || name.contains('/')
        {
            return Err(GuestProtoError::Invalid { field: "secrets" });
        }
    }
    if configure.server_command.is_empty() || configure.server_command[0].is_empty()
    {
        return Err(GuestProtoError::Invalid {
            field: "server_command",
        });
    }
    if configure.server_command.len() > MAX_COMMAND_ARGS
    {
        return Err(GuestProtoError::OutOfRange {
            field: "server_command",
        });
    }
    for argument in &configure.server_command
    {
        no_nul("server_command", argument, MAX_COMMAND_ARG_BYTES)?;
    }
    Ok(())
}

fn in_range(field: &'static str, value: f64, max: f64) -> Result<(), GuestProtoError>
{
    if value.is_finite() && (0.0..=max).contains(&value)
    {
        Ok(())
    }
    else
    {
        Err(GuestProtoError::OutOfRange { field })
    }
}

fn single_line(field: &'static str, value: &str, max: usize) -> Result<(), GuestProtoError>
{
    if value.len() > max
    {
        return Err(GuestProtoError::TooLong { field, max });
    }
    if value.chars().any(|c| c.is_control() && c != '\t')
    {
        return Err(GuestProtoError::ForbiddenCharacter { field });
    }
    Ok(())
}

fn no_nul(field: &'static str, value: &str, max: usize) -> Result<(), GuestProtoError>
{
    if value.len() > max
    {
        return Err(GuestProtoError::TooLong { field, max });
    }
    if value.contains('\0')
    {
        return Err(GuestProtoError::ForbiddenCharacter { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{
        ConsoleCommand, Log, PrepareSnapshot, Ready, ResumeWrites, Shutdown, ShutdownComplete,
        SnapshotPrepared,
    };
    use std::collections::HashMap;

    fn guest(body: GuestBody) -> Vec<u8>
    {
        GuestMessage { body: Some(body) }.encode_to_vec()
    }

    fn host(body: HostBody) -> Vec<u8>
    {
        HostMessage { body: Some(body) }.encode_to_vec()
    }

    fn health(tps: f64, mspt: f64, players: u32, heap_used_bytes: u64) -> Vec<u8>
    {
        guest(GuestBody::Health(Health {
            tps,
            mspt,
            players,
            heap_used_bytes,
        }))
    }

    fn configure() -> Configure
    {
        Configure {
            instance_id: "inst-1".to_owned(),
            generation: 3,
            env: HashMap::from([("EULA".to_owned(), "true".to_owned())]),
            secrets: HashMap::from([("rcon.password".to_owned(), b"hunter2".to_vec())]),
            memory_mib: 4096,
            server_command: vec![
                "java".to_owned(),
                "-jar".to_owned(),
                "server.jar".to_owned(),
            ],
        }
    }

    #[test]
    fn every_guest_body_round_trips()
    {
        let bodies = [
            GuestBody::Ready(Ready {
                server_version: "1.21.4".to_owned(),
            }),
            GuestBody::Health(Health {
                tps: 20.0,
                mspt: 12.5,
                players: 7,
                heap_used_bytes: 2 << 30,
            }),
            GuestBody::Log(Log {
                line: "[Server] Done (3.2s)!\tok".to_owned(),
            }),
            GuestBody::ShutdownComplete(ShutdownComplete { exit_code: -1 }),
            GuestBody::SnapshotPrepared(SnapshotPrepared {
                ok: false,
                error: "save failed".to_owned(),
            }),
        ];
        for body in bodies
        {
            let decoded = decode_guest_message(&guest(body.clone())).unwrap();
            assert_eq!(decoded.body, Some(body));
        }
    }

    #[test]
    fn every_host_body_round_trips()
    {
        let bodies = [
            HostBody::Configure(configure()),
            HostBody::ConsoleCommand(ConsoleCommand {
                command: "say hi".to_owned(),
            }),
            HostBody::PrepareSnapshot(PrepareSnapshot {}),
            HostBody::ResumeWrites(ResumeWrites {}),
            HostBody::Shutdown(Shutdown {
                deadline_ms: 30_000,
            }),
        ];
        for body in bodies
        {
            let decoded = decode_host_message(&host(body.clone())).unwrap();
            assert_eq!(decoded.body, Some(body));
        }
    }

    #[test]
    fn missing_body_is_rejected()
    {
        assert_eq!(decode_guest_message(&[]), Err(GuestProtoError::MissingBody));
        assert_eq!(decode_host_message(&[]), Err(GuestProtoError::MissingBody));
    }

    #[test]
    fn malformed_bytes_are_rejected()
    {
        assert!(matches!(
            decode_guest_message(&[0x0a, 0x05, 0x01]),
            Err(GuestProtoError::Decode(_))
        ));
        assert!(matches!(
            decode_guest_message(&[0xff, 0xff, 0xff]),
            Err(GuestProtoError::Decode(_))
        ));
        assert!(matches!(
            decode_host_message(&[0x12, 0x80]),
            Err(GuestProtoError::Decode(_))
        ));
        let invalid_utf8 = [0x1a, 0x04, 0x0a, 0x02, 0xc3, 0x28];
        assert!(matches!(
            decode_guest_message(&invalid_utf8),
            Err(GuestProtoError::Decode(_))
        ));
    }

    #[test]
    fn health_bounds_are_inclusive()
    {
        assert!(decode_guest_message(&health(0.0, 0.0, 0, 0)).is_ok());
        assert!(
            decode_guest_message(&health(MAX_TPS, MAX_MSPT, MAX_PLAYERS, MAX_HEAP_BYTES)).is_ok()
        );
    }

    #[test]
    fn health_rejects_bad_tps()
    {
        for tps in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 1000.1]
        {
            assert_eq!(
                decode_guest_message(&health(tps, 1.0, 1, 1)),
                Err(GuestProtoError::OutOfRange { field: "tps" })
            );
        }
    }

    #[test]
    fn health_rejects_bad_mspt()
    {
        for mspt in [f64::NAN, f64::INFINITY, -1.0, 60_000.5]
        {
            assert_eq!(
                decode_guest_message(&health(20.0, mspt, 1, 1)),
                Err(GuestProtoError::OutOfRange { field: "mspt" })
            );
        }
    }

    #[test]
    fn health_rejects_too_many_players()
    {
        assert_eq!(
            decode_guest_message(&health(20.0, 1.0, MAX_PLAYERS + 1, 1)),
            Err(GuestProtoError::OutOfRange { field: "players" })
        );
    }

    #[test]
    fn health_rejects_huge_heap()
    {
        assert_eq!(
            decode_guest_message(&health(20.0, 1.0, 1, MAX_HEAP_BYTES + 1)),
            Err(GuestProtoError::OutOfRange {
                field: "heap_used_bytes"
            })
        );
    }

    #[test]
    fn log_line_limit()
    {
        let at_limit = "a".repeat(MAX_LOG_LINE_BYTES);
        assert!(decode_guest_message(&guest(GuestBody::Log(Log { line: at_limit }))).is_ok());
        let over = "a".repeat(MAX_LOG_LINE_BYTES + 1);
        assert_eq!(
            decode_guest_message(&guest(GuestBody::Log(Log { line: over }))),
            Err(GuestProtoError::TooLong {
                field: "line",
                max: MAX_LOG_LINE_BYTES
            })
        );
    }

    #[test]
    fn log_line_limit_counts_bytes_not_chars()
    {
        let line = "é".repeat(MAX_LOG_LINE_BYTES / 2 + 1);
        assert!(matches!(
            decode_guest_message(&guest(GuestBody::Log(Log { line }))),
            Err(GuestProtoError::TooLong { .. })
        ));
    }

    #[test]
    fn server_version_limit()
    {
        let over = "1".repeat(MAX_SERVER_VERSION_BYTES + 1);
        assert_eq!(
            decode_guest_message(&guest(GuestBody::Ready(Ready {
                server_version: over
            }))),
            Err(GuestProtoError::TooLong {
                field: "server_version",
                max: MAX_SERVER_VERSION_BYTES
            })
        );
    }

    #[test]
    fn snapshot_error_limit()
    {
        let over = "e".repeat(MAX_ERROR_BYTES + 1);
        assert_eq!(
            decode_guest_message(&guest(GuestBody::SnapshotPrepared(SnapshotPrepared {
                ok: false,
                error: over
            }))),
            Err(GuestProtoError::TooLong {
                field: "error",
                max: MAX_ERROR_BYTES
            })
        );
    }

    #[test]
    fn control_characters_are_rejected_except_tab()
    {
        for line in [
            "a\nb",
            "a\rb",
            "\u{1b}[31mred",
            "nul\0",
            "del\u{7f}",
            "c1\u{85}",
        ]
        {
            assert_eq!(
                decode_guest_message(&guest(GuestBody::Log(Log {
                    line: line.to_owned()
                }))),
                Err(GuestProtoError::ForbiddenCharacter { field: "line" }),
                "{line:?}"
            );
        }
        assert_eq!(
            decode_guest_message(&guest(GuestBody::Ready(Ready {
                server_version: "1\n2".to_owned()
            }))),
            Err(GuestProtoError::ForbiddenCharacter {
                field: "server_version"
            })
        );
        assert_eq!(
            decode_guest_message(&guest(GuestBody::SnapshotPrepared(SnapshotPrepared {
                ok: false,
                error: "x\ny".to_owned()
            }))),
            Err(GuestProtoError::ForbiddenCharacter { field: "error" })
        );
        assert!(
            decode_guest_message(&guest(GuestBody::Log(Log {
                line: "a\tb".to_owned()
            })))
            .is_ok()
        );
    }

    #[test]
    fn any_exit_code_is_accepted()
    {
        for exit_code in [i32::MIN, -9, 0, 1, i32::MAX]
        {
            assert!(
                decode_guest_message(&guest(GuestBody::ShutdownComplete(ShutdownComplete {
                    exit_code
                })))
                .is_ok()
            );
        }
    }

    #[test]
    fn console_command_limits()
    {
        let at_limit = "x".repeat(MAX_CONSOLE_COMMAND_BYTES);
        assert!(
            decode_host_message(&host(HostBody::ConsoleCommand(ConsoleCommand {
                command: at_limit
            })))
            .is_ok()
        );
        let over = "x".repeat(MAX_CONSOLE_COMMAND_BYTES + 1);
        assert_eq!(
            decode_host_message(&host(HostBody::ConsoleCommand(ConsoleCommand {
                command: over
            }))),
            Err(GuestProtoError::TooLong {
                field: "command",
                max: MAX_CONSOLE_COMMAND_BYTES
            })
        );
        for command in ["stop\nop attacker", "say\r", "a\0"]
        {
            assert_eq!(
                decode_host_message(&host(HostBody::ConsoleCommand(ConsoleCommand {
                    command: command.to_owned()
                }))),
                Err(GuestProtoError::ForbiddenCharacter { field: "command" })
            );
        }
    }

    #[test]
    fn shutdown_deadline_limit()
    {
        assert!(
            decode_host_message(&host(HostBody::Shutdown(Shutdown {
                deadline_ms: MAX_SHUTDOWN_DEADLINE_MS
            })))
            .is_ok()
        );
        assert_eq!(
            decode_host_message(&host(HostBody::Shutdown(Shutdown {
                deadline_ms: MAX_SHUTDOWN_DEADLINE_MS + 1
            }))),
            Err(GuestProtoError::OutOfRange {
                field: "deadline_ms"
            })
        );
    }

    fn configure_error(edit: impl FnOnce(&mut Configure)) -> GuestProtoError
    {
        let mut message = configure();
        edit(&mut message);
        decode_host_message(&host(HostBody::Configure(message))).unwrap_err()
    }

    #[test]
    fn configure_rejects_bad_instance_id()
    {
        assert_eq!(
            configure_error(|c| c.instance_id.clear()),
            GuestProtoError::Invalid {
                field: "instance_id"
            }
        );
        assert_eq!(
            configure_error(|c| c.instance_id = "a\nb".to_owned()),
            GuestProtoError::ForbiddenCharacter {
                field: "instance_id"
            }
        );
        assert_eq!(
            configure_error(|c| c.instance_id = "i".repeat(MAX_INSTANCE_ID_BYTES + 1)),
            GuestProtoError::TooLong {
                field: "instance_id",
                max: MAX_INSTANCE_ID_BYTES
            }
        );
    }

    #[test]
    fn configure_rejects_zero_memory()
    {
        assert_eq!(
            configure_error(|c| c.memory_mib = 0),
            GuestProtoError::OutOfRange {
                field: "memory_mib"
            }
        );
    }

    #[test]
    fn configure_rejects_bad_env()
    {
        assert_eq!(
            configure_error(|c| {
                c.env.insert("A=B".to_owned(), String::new());
            }),
            GuestProtoError::Invalid { field: "env" }
        );
        assert_eq!(
            configure_error(|c| {
                c.env.insert(String::new(), "v".to_owned());
            }),
            GuestProtoError::Invalid { field: "env" }
        );
        assert_eq!(
            configure_error(|c| {
                c.env.insert("K".to_owned(), "a\0b".to_owned());
            }),
            GuestProtoError::ForbiddenCharacter { field: "env" }
        );
        assert_eq!(
            configure_error(|c| {
                c.env
                    .insert("K".to_owned(), "v".repeat(MAX_ENV_VALUE_BYTES + 1));
            }),
            GuestProtoError::TooLong {
                field: "env",
                max: MAX_ENV_VALUE_BYTES
            }
        );
    }

    #[test]
    fn configure_accepts_multiline_env_values()
    {
        let mut message = configure();
        message
            .env
            .insert("MOTD".to_owned(), "line one\nline two".to_owned());
        assert!(decode_host_message(&host(HostBody::Configure(message))).is_ok());
    }

    #[test]
    fn configure_rejects_unsafe_secret_names()
    {
        for name in ["", ".", "..", "../etc/passwd", "a/b", "a\nb"]
        {
            let error = configure_error(|c| {
                c.secrets.insert(name.to_owned(), b"x".to_vec());
            });
            assert!(
                matches!(
                    error,
                    GuestProtoError::Invalid { field: "secrets" }
                        | GuestProtoError::ForbiddenCharacter { field: "secrets" }
                ),
                "{name:?}: {error:?}"
            );
        }
    }

    #[test]
    fn configure_rejects_bad_server_command()
    {
        assert_eq!(
            configure_error(|c| c.server_command.clear()),
            GuestProtoError::Invalid {
                field: "server_command"
            }
        );
        assert_eq!(
            configure_error(|c| c.server_command[0].clear()),
            GuestProtoError::Invalid {
                field: "server_command"
            }
        );
        assert_eq!(
            configure_error(|c| c.server_command.push("a\0".to_owned())),
            GuestProtoError::ForbiddenCharacter {
                field: "server_command"
            }
        );
        assert_eq!(
            configure_error(|c| c.server_command = vec!["x".to_owned(); MAX_COMMAND_ARGS + 1]),
            GuestProtoError::OutOfRange {
                field: "server_command"
            }
        );
        assert_eq!(
            configure_error(|c| c.server_command.push("y".repeat(MAX_COMMAND_ARG_BYTES + 1))),
            GuestProtoError::TooLong {
                field: "server_command",
                max: MAX_COMMAND_ARG_BYTES
            }
        );
    }

    #[test]
    fn configure_debug_hides_secret_values()
    {
        let rendered = format!("{:?}", configure());
        assert!(rendered.contains("rcon.password"));
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("104, 117"));
    }
}
