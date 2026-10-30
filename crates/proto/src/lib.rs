//! Generated types, client, and server for the `quarry.agent.v1` control protocol.

/// Version 1 of the agent protocol.
pub mod v1
{
    #![allow(clippy::large_enum_variant)]

    tonic::include_proto!("quarry.agent.v1");

    impl std::fmt::Display for Phase
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
        {
            let name = self.as_str_name();
            f.write_str(name.strip_prefix("PHASE_").unwrap_or(name))
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::v1::{
        AgentMessage, ControlMessage, DesiredState, Hello, Phase, agent_message, control_message,
    };
    use prost::Message;

    #[test]
    fn agent_message_round_trips()
    {
        let message = AgentMessage {
            seq: 0,
            ack: 7,
            body: Some(agent_message::Body::Hello(Hello {
                node_id: "node-1".to_owned(),
                agent_version: "1.0.0".to_owned(),
                capabilities: None,
                inventory: None,
            })),
        };
        let decoded = AgentMessage::decode(message.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn desired_state_uses_tag_16()
    {
        let message = ControlMessage {
            seq: 3,
            ack: 0,
            body: Some(control_message::Body::Desired(DesiredState::default())),
        };
        let bytes = message.encode_to_vec();
        assert!(bytes.windows(2).any(|w| w == [0x82, 0x01]));
    }

    #[test]
    fn phase_displays_short_name()
    {
        assert_eq!(Phase::Running.to_string(), "RUNNING");
        assert_eq!(Phase::Rejected.to_string(), "REJECTED");
    }
    #[test]
    fn health_wake_and_live_use_assigned_wire_tags()
    {
        use super::v1::{InstanceHealth, LiveMetrics, WakeRequest};
        let health = AgentMessage {
            seq: 0,
            ack: 0,
            body: Some(agent_message::Body::Health(InstanceHealth {
                instance_id: "i".into(),
                cpu_usec_total: 9001,
                ..Default::default()
            })),
        };
        let bytes = health.encode_to_vec();
        assert_eq!(&bytes[..2], &[0x82, 0x01]);
        assert_eq!(AgentMessage::decode(bytes.as_slice()).unwrap(), health);
        let wake = AgentMessage {
            body: Some(agent_message::Body::Wake(WakeRequest {
                instance_id: "i".into(),
                requested_at_unix_ms: 42,
            })),
            ..Default::default()
        };
        assert_eq!(&wake.encode_to_vec()[..2], &[0x8a, 0x01]);
        let live = ControlMessage {
            seq: 1,
            body: Some(control_message::Body::Live(LiveMetrics {
                instance_id: "i".into(),
                until_unix_ms: 42,
            })),
            ..Default::default()
        };
        let bytes = live.encode_to_vec();
        assert!(bytes.windows(2).any(|w| w == [0x8a, 0x01]));
        assert_eq!(ControlMessage::decode(bytes.as_slice()).unwrap(), live);
    }
}
