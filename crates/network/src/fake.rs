use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::instance::{InstanceNetworkSpec, InterfaceCounters, NetworkAttachment};
use crate::node::NodeNetwork;
use crate::public::{ProxyNeighbour, PublicState};
use crate::responder::SleepResponder;
use crate::{
    Network, PublicIpMetrics, PublicIpMode, PublicIpv4Config, PublicWake,
    ensure_subnet_change_allowed, nft, state_file,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FakeOperation
{
    ConfigureNode,
    ConfigurePublic,
    AttachPublic,
    DetachPublic,
    SetPublicMode,
    ApplyPublic,
    CleanupPublic,
    Attach,
    Detach,
    Counters,
    WireguardPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeCall
{
    ConfigureNode(NodeNetwork),
    ConfigurePublic(PublicIpv4Config),
    AttachPublic(String, Ipv4Addr),
    DetachPublic(String),
    SetPublicMode(String, PublicIpMode),
    CleanupPublic(Ipv4Addr),
    Attach(InstanceNetworkSpec),
    Detach(String),
    Counters(String),
    WireguardPublicKey,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedFake
{
    node: Option<NodeNetwork>,
    attachments: BTreeMap<String, NetworkAttachment>,
    #[serde(default)]
    specs: BTreeMap<String, InstanceNetworkSpec>,
    #[serde(default)]
    public: PublicState,
}

#[derive(Debug)]
struct FakeState
{
    persisted: PersistedFake,
    counters: BTreeMap<String, InterfaceCounters>,
    calls: Vec<FakeCall>,
    pending_failures: Vec<(FakeOperation, String)>,
    wireguard_public_key: Option<String>,
    nft_transactions: Vec<serde_json::Value>,
    proxies: std::collections::BTreeSet<ProxyNeighbour>,
    applied_public: Option<PublicState>,
}

#[derive(Debug)]
pub struct FakeNetwork
{
    path: Option<PathBuf>,
    state: Mutex<FakeState>,
    responder: SleepResponder,
}

impl FakeNetwork
{
    pub const DEFAULT_WIREGUARD_PUBLIC_KEY: &'static str =
        "ZmFrZS13aXJlZ3VhcmQtcHVibGljLWtleS0wMDAwMDA=";

    pub fn new(path: Option<PathBuf>) -> Result<FakeNetwork, NetworkError>
    {
        let persisted = match &path
        {
            Some(path) => state_file::load(path)?.unwrap_or_default(),
            None => PersistedFake::default(),
        };
        let fake = FakeNetwork {
            path,
            state: Mutex::new(FakeState {
                persisted,
                counters: BTreeMap::new(),
                calls: Vec::new(),
                pending_failures: Vec::new(),
                wireguard_public_key: Some(Self::DEFAULT_WIREGUARD_PUBLIC_KEY.to_string()),
                nft_transactions: Vec::new(),
                proxies: Default::default(),
                applied_public: None,
            }),
            responder: SleepResponder::new(Ipv4Addr::LOCALHOST),
        };
        {
            let mut state = fake.lock();
            if let Some(node) = state.persisted.node.clone()
            {
                state
                    .nft_transactions
                    .push(nft::node_ruleset(node.subnet, None));
            }
            let specs: Vec<_> = state.persisted.specs.values().cloned().collect();
            for spec in specs
            {
                state.nft_transactions.push(nft::instance_rules(&spec));
            }
            if state.persisted.node.is_some() || state.persisted.public != PublicState::default()
            {
                fake.apply_public(&mut state)?;
            }
        }
        Ok(fake)
    }

    pub fn set_counters(&self, instance_id: &str, counters: InterfaceCounters)
    {
        self.lock()
            .counters
            .insert(instance_id.to_string(), counters);
    }

    pub fn attachments(&self) -> BTreeMap<String, NetworkAttachment>
    {
        self.lock().persisted.attachments.clone()
    }

    pub fn node_config(&self) -> Option<NodeNetwork>
    {
        self.lock().persisted.node.clone()
    }

    pub fn calls(&self) -> Vec<FakeCall>
    {
        self.lock().calls.clone()
    }

    pub fn responder_address(&self, instance_id: &str) -> Option<SocketAddr>
    {
        self.responder.address(instance_id)
    }

    pub fn public_bindings(&self) -> BTreeMap<String, Ipv4Addr>
    {
        self.lock()
            .persisted
            .public
            .bindings
            .iter()
            .map(|(id, binding)| (id.clone(), binding.address))
            .collect()
    }

    pub fn public_mode(&self, instance_id: &str) -> Option<PublicIpMode>
    {
        self.lock()
            .persisted
            .public
            .bindings
            .get(instance_id)
            .map(|binding| binding.mode)
    }

    pub fn nft_transactions(&self) -> Vec<serde_json::Value>
    {
        self.lock().nft_transactions.clone()
    }

    pub fn proxy_neighbours(&self) -> Vec<(String, Ipv4Addr)>
    {
        self.lock()
            .proxies
            .iter()
            .map(|proxy| (proxy.interface.clone(), proxy.address))
            .collect()
    }

    pub fn fail_next(&self, operation: FakeOperation, message: impl Into<String>)
    {
        self.lock()
            .pending_failures
            .push((operation, message.into()));
    }

    pub fn set_wireguard_public_key(&self, key: Option<String>)
    {
        self.lock().wireguard_public_key = key;
    }

    fn lock(&self) -> MutexGuard<'_, FakeState>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(
        &self,
        call: FakeCall,
        operation: FakeOperation,
    ) -> Result<MutexGuard<'_, FakeState>, NetworkError>
    {
        let mut state = self.lock();
        state.calls.push(call);
        if let Some(index) = state
            .pending_failures
            .iter()
            .position(|(op, _)| *op == operation)
        {
            let (_, message) = state.pending_failures.remove(index);
            return Err(NetworkError::Injected(message));
        }
        Ok(state)
    }

    fn persist(&self, state: &FakeState) -> Result<(), NetworkError>
    {
        match &self.path
        {
            Some(path) => state_file::save(path, &state.persisted),
            None => Ok(()),
        }
    }

    fn apply_public(&self, state: &mut FakeState) -> Result<(), NetworkError>
    {
        self.responder.prepare(&mut state.persisted.public)?;
        if state.applied_public.as_ref() == Some(&state.persisted.public)
        {
            return Ok(());
        }
        self.persist(state)?;
        if let Some(index) = state
            .pending_failures
            .iter()
            .position(|(operation, _)| *operation == FakeOperation::ApplyPublic)
        {
            let (_, message) = state.pending_failures.remove(index);
            return Err(NetworkError::Injected(message));
        }
        let retired_addresses: std::collections::BTreeSet<_> = state
            .persisted
            .public
            .retired_bindings
            .iter()
            .map(|binding| binding.address)
            .collect();
        if !retired_addresses.is_empty()
        {
            state
                .nft_transactions
                .push(nft::public_retirement_guard(&state.persisted.public));
        }
        for address in retired_addresses
        {
            state.calls.push(FakeCall::CleanupPublic(address));
            if let Some(index) = state
                .pending_failures
                .iter()
                .position(|(operation, _)| *operation == FakeOperation::CleanupPublic)
            {
                let (_, message) = state.pending_failures.remove(index);
                return Err(NetworkError::Injected(message));
            }
        }
        state
            .nft_transactions
            .push(nft::public_rules(&state.persisted.public));
        state.proxies = state.persisted.public.proxies();
        let mut persisted = state.persisted.clone();
        persisted.public.retired_proxies.clear();
        persisted.public.retired_bindings.clear();
        if let Some(path) = &self.path
        {
            state_file::save(path, &persisted)?;
        }
        state.persisted = persisted;
        self.responder.publish(&state.persisted.public);
        state.applied_public = Some(state.persisted.public.clone());
        Ok(())
    }
}

#[async_trait]
impl Network for FakeNetwork
{
    async fn configure_node(&self, node: &NodeNetwork) -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::ConfigureNode(node.clone()),
            FakeOperation::ConfigureNode,
        )?;
        node.validate()?;
        ensure_subnet_change_allowed(
            state.persisted.node.as_ref(),
            !state.persisted.attachments.is_empty(),
            node,
        )?;
        state.persisted.node = Some(node.clone());
        self.persist(&state)?;
        let uplink = (!state.persisted.public.config.uplink_interface.is_empty())
            .then_some(state.persisted.public.config.uplink_interface.as_str());
        let rules = nft::node_ruleset(node.subnet, uplink);
        state.nft_transactions.push(rules);
        Ok(())
    }

    async fn configure_public(&self, config: &PublicIpv4Config) -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::ConfigurePublic(config.clone()),
            FakeOperation::ConfigurePublic,
        )?;
        // Nothing is routed through an uplink here, so a pool does not need one.
        state.persisted.public.configure(config, false)?;
        self.apply_public(&mut state)
    }

    fn validate_public_ipv4(&self, instance_id: &str, address: &str) -> Result<(), NetworkError>
    {
        self.lock().persisted.public.validate(instance_id, address)
    }

    async fn attach_public(&self, instance_id: &str, address: Ipv4Addr)
    -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::AttachPublic(instance_id.to_string(), address),
            FakeOperation::AttachPublic,
        )?;
        let guest_ip = state
            .persisted
            .attachments
            .get(instance_id)
            .ok_or_else(|| NetworkError::NotAttached(instance_id.to_string()))?
            .guest_ip;
        state
            .persisted
            .public
            .attach(instance_id, address, guest_ip)?;
        self.apply_public(&mut state)
    }

    async fn detach_public(&self, instance_id: &str) -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::DetachPublic(instance_id.to_string()),
            FakeOperation::DetachPublic,
        )?;
        state.persisted.public.remove(instance_id);
        self.apply_public(&mut state)
    }

    async fn set_public_mode(
        &self,
        instance_id: &str,
        mode: PublicIpMode,
    ) -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::SetPublicMode(instance_id.to_string(), mode),
            FakeOperation::SetPublicMode,
        )?;
        if state.persisted.public.bindings.contains_key(instance_id)
        {
            state.persisted.public.set_mode(instance_id, mode);
            self.apply_public(&mut state)?;
        }
        Ok(())
    }

    fn subscribe_wakes(&self) -> tokio::sync::broadcast::Receiver<PublicWake>
    {
        self.responder.subscribe()
    }

    fn public_metrics(&self) -> PublicIpMetrics
    {
        self.responder.metrics()
    }

    async fn attach(&self, spec: &InstanceNetworkSpec) -> Result<NetworkAttachment, NetworkError>
    {
        let mut state = self.begin(FakeCall::Attach(spec.clone()), FakeOperation::Attach)?;
        let subnet = state
            .persisted
            .node
            .as_ref()
            .map(|node| node.subnet)
            .ok_or(NetworkError::NodeNotConfigured)?;
        spec.validate(subnet)?;
        spec.ensure_address_is_free(
            state
                .persisted
                .attachments
                .values()
                .map(|attachment| (attachment.instance_id.as_str(), attachment.guest_ip)),
        )?;
        let attachment = spec.attachment(subnet);
        let changed = state.persisted.specs.get(&spec.instance_id) != Some(spec);
        state
            .persisted
            .specs
            .insert(spec.instance_id.clone(), spec.clone());
        if state.persisted.attachments.get(&spec.instance_id) != Some(&attachment)
        {
            state
                .persisted
                .attachments
                .insert(spec.instance_id.clone(), attachment.clone());
            self.persist(&state)?;
        }
        if changed
        {
            self.persist(&state)?;
            state.nft_transactions.push(nft::instance_rules(spec));
        }
        if state
            .persisted
            .public
            .bindings
            .contains_key(&spec.instance_id)
        {
            if state.persisted.public.bindings[&spec.instance_id].guest_ip != spec.guest_ip
            {
                state
                    .persisted
                    .public
                    .set_mode(&spec.instance_id, PublicIpMode::Starting);
            }
            state
                .persisted
                .public
                .update_guest_ip(&spec.instance_id, spec.guest_ip);
            self.apply_public(&mut state)?;
        }
        Ok(attachment)
    }

    async fn detach(&self, instance_id: &str) -> Result<(), NetworkError>
    {
        let mut state = self.begin(
            FakeCall::Detach(instance_id.to_string()),
            FakeOperation::Detach,
        )?;
        state.persisted.public.remove(instance_id);
        self.apply_public(&mut state)?;
        state.counters.remove(instance_id);
        state.persisted.specs.remove(instance_id);
        if state.persisted.attachments.remove(instance_id).is_some()
        {
            self.persist(&state)?;
        }
        Ok(())
    }

    async fn counters(
        &self,
        attachment: &NetworkAttachment,
    ) -> Result<InterfaceCounters, NetworkError>
    {
        let state = self.begin(
            FakeCall::Counters(attachment.instance_id.clone()),
            FakeOperation::Counters,
        )?;
        if !state
            .persisted
            .attachments
            .contains_key(&attachment.instance_id)
        {
            return Err(NetworkError::NotAttached(attachment.instance_id.clone()));
        }
        Ok(state
            .counters
            .get(&attachment.instance_id)
            .copied()
            .unwrap_or_default())
    }

    async fn wireguard_public_key(&self) -> Result<Option<String>, NetworkError>
    {
        let state = self.begin(
            FakeCall::WireguardPublicKey,
            FakeOperation::WireguardPublicKey,
        )?;
        Ok(state.wireguard_public_key.clone())
    }
}

#[cfg(test)]
mod tests
{
    use std::net::Ipv4Addr;

    use super::*;
    use crate::instance::AttachMode;
    use crate::ipam::guest_mac;
    use crate::subnet::Subnet;
    use crate::wireguard::is_valid_key;

    fn node() -> NodeNetwork
    {
        NodeNetwork {
            subnet: Subnet::parse("10.0.0.0/24").unwrap(),
            region: "eu-1".to_string(),
            wireguard_listen_port: 0,
            wireguard_address: None,
            peers: Vec::new(),
        }
    }

    fn spec(id: &str, last_octet: u8) -> InstanceNetworkSpec
    {
        let ip = Ipv4Addr::new(10, 0, 0, last_octet);
        InstanceNetworkSpec {
            instance_id: id.to_string(),
            world_id: "world".to_string(),
            guest_ip: ip,
            guest_mac: guest_mac(ip),
            egress_mbit: 100,
            ports: vec![25565],
            mode: AttachMode::Tap,
            uid: 1000,
            gid: 1000,
        }
    }

    #[tokio::test]
    async fn attach_requires_a_configured_node()
    {
        let fake = FakeNetwork::new(None).unwrap();
        assert!(matches!(
            fake.attach(&spec("a", 5)).await,
            Err(NetworkError::NodeNotConfigured)
        ));
    }

    #[tokio::test]
    async fn attach_and_detach_are_idempotent()
    {
        let fake = FakeNetwork::new(None).unwrap();
        fake.configure_node(&node()).await.unwrap();
        let first = fake.attach(&spec("a", 5)).await.unwrap();
        let second = fake.attach(&spec("a", 5)).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(first.prefix_len, 24);
        assert_eq!(fake.attachments().len(), 1);
        fake.detach("a").await.unwrap();
        fake.detach("a").await.unwrap();
        fake.detach("never-attached").await.unwrap();
        assert!(fake.attachments().is_empty());
        assert_eq!(
            fake.calls(),
            vec![
                FakeCall::ConfigureNode(node()),
                FakeCall::Attach(spec("a", 5)),
                FakeCall::Attach(spec("a", 5)),
                FakeCall::Detach("a".to_string()),
                FakeCall::Detach("a".to_string()),
                FakeCall::Detach("never-attached".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn rejects_address_conflicts_and_invalid_specs()
    {
        let fake = FakeNetwork::new(None).unwrap();
        fake.configure_node(&node()).await.unwrap();
        fake.attach(&spec("a", 5)).await.unwrap();
        assert!(matches!(
            fake.attach(&spec("b", 5)).await,
            Err(NetworkError::InvalidSpec { .. })
        ));
        assert!(matches!(
            fake.attach(&spec("c", 1)).await,
            Err(NetworkError::InvalidSpec { .. })
        ));
    }

    #[tokio::test]
    async fn attachments_survive_recreation_from_the_state_file()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-network.json");
        let attachment = {
            let fake = FakeNetwork::new(Some(path.clone())).unwrap();
            fake.configure_node(&node()).await.unwrap();
            fake.attach(&spec("b", 9)).await.unwrap();
            fake.attach(&spec("a", 5)).await.unwrap()
        };
        let restarted = FakeNetwork::new(Some(path.clone())).unwrap();
        assert_eq!(restarted.node_config(), Some(node()));
        assert_eq!(restarted.attachments().get("a"), Some(&attachment));
        assert_eq!(restarted.attachments().len(), 2);
        assert_eq!(restarted.attach(&spec("a", 5)).await.unwrap(), attachment);
        restarted.detach("b").await.unwrap();
        let again = FakeNetwork::new(Some(path)).unwrap();
        assert_eq!(again.attachments().keys().collect::<Vec<_>>(), vec!["a"]);
    }

    #[tokio::test]
    async fn counters_are_settable_and_require_an_attachment()
    {
        let fake = FakeNetwork::new(None).unwrap();
        fake.configure_node(&node()).await.unwrap();
        let attachment = fake.attach(&spec("a", 5)).await.unwrap();
        assert_eq!(
            fake.counters(&attachment).await.unwrap(),
            InterfaceCounters::default()
        );
        let counters = InterfaceCounters {
            rx_bytes: 10,
            tx_bytes: 20,
        };
        fake.set_counters("a", counters);
        assert_eq!(fake.counters(&attachment).await.unwrap(), counters);
        fake.detach("a").await.unwrap();
        assert!(matches!(
            fake.counters(&attachment).await,
            Err(NetworkError::NotAttached(id)) if id == "a"
        ));
    }

    #[tokio::test]
    async fn injected_failures_fire_once_for_their_operation()
    {
        let fake = FakeNetwork::new(None).unwrap();
        fake.configure_node(&node()).await.unwrap();
        fake.fail_next(FakeOperation::Attach, "boom");
        fake.detach("a").await.unwrap();
        assert!(matches!(
            fake.attach(&spec("a", 5)).await,
            Err(NetworkError::Injected(message)) if message == "boom"
        ));
        assert!(fake.attachments().is_empty());
        fake.attach(&spec("a", 5)).await.unwrap();
    }

    #[tokio::test]
    async fn refuses_to_change_subnet_under_attached_instances()
    {
        let fake = FakeNetwork::new(None).unwrap();
        fake.configure_node(&node()).await.unwrap();
        fake.attach(&spec("a", 5)).await.unwrap();
        let moved = NodeNetwork {
            subnet: Subnet::parse("10.9.0.0/24").unwrap(),
            ..node()
        };
        assert!(fake.configure_node(&moved).await.is_err());
        fake.configure_node(&node()).await.unwrap();
        fake.detach("a").await.unwrap();
        fake.configure_node(&moved).await.unwrap();
        assert_eq!(fake.node_config(), Some(moved));
    }

    #[tokio::test]
    async fn reports_a_wireguard_key()
    {
        let fake = FakeNetwork::new(None).unwrap();
        let key = fake.wireguard_public_key().await.unwrap().unwrap();
        assert!(is_valid_key(&key));
        fake.set_wireguard_public_key(None);
        assert_eq!(fake.wireguard_public_key().await.unwrap(), None);
    }
}
