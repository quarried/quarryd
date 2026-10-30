mod command;
mod netlink;
mod netns;
mod tun;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use async_trait::async_trait;
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::error::NetworkError;
use crate::instance::{AttachMode, InstanceNetworkSpec, InterfaceCounters, NetworkAttachment};
use crate::ipam::{mac_with_prefix, parse_mac};
use crate::names::InterfaceNames;
use crate::nft::{self, WorldMembership, world_set_name};
use crate::node::NodeNetwork;
use crate::public::PublicState;
use crate::responder::SleepResponder;
use crate::subnet::Subnet;
use crate::wireguard::{self, IpPrefix, is_valid_key};
use crate::{
    Network, NetworkingConfig, PublicIpMetrics, PublicIpMode, PublicIpv4Config, PublicWake,
    ensure_subnet_change_allowed, state_file, tc,
};

pub const GATEWAY_LINK: &str = "quarry0";
const STATE_FILE: &str = "network-state.json";
const WIREGUARD_KEY_FILE: &str = "wireguard.key";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState
{
    node: Option<NodeNetwork>,
    instances: BTreeMap<String, InstanceRecord>,
    #[serde(default)]
    public: PublicState,
    #[serde(skip)]
    applied_public: Option<PublicState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstanceRecord
{
    spec: InstanceNetworkSpec,
    complete: bool,
}

impl InstanceRecord
{
    fn has_same_links(&self, spec: &InstanceNetworkSpec) -> bool
    {
        self.spec.mode == spec.mode
            && self.spec.guest_ip == spec.guest_ip
            && self.spec.normalized_guest_mac() == spec.normalized_guest_mac()
            && self.spec.uid == spec.uid
            && self.spec.gid == spec.gid
    }

    fn world_set(&self) -> String
    {
        world_set_name(&self.spec.world_id, &self.spec.instance_id)
    }
}

impl PersistedState
{
    fn world_membership(&self, instance_id: &str) -> Option<WorldMembership>
    {
        let record = self.instances.get(instance_id)?;
        let set_name = record.world_set();
        let shared = self
            .instances
            .iter()
            .any(|(other_id, other)| other_id != instance_id && other.world_set() == set_name);
        Some(WorldMembership {
            set_name,
            guest_ip: record.spec.guest_ip,
            remove_set: !shared,
        })
    }
}

pub struct Networking
{
    config: NetworkingConfig,
    state_path: PathBuf,
    key_path: PathBuf,
    state: Mutex<PersistedState>,
    public_claims: RwLock<PublicState>,
    responder: SleepResponder,
}

impl Networking
{
    pub fn new(config: NetworkingConfig) -> Result<Networking, NetworkError>
    {
        fs::create_dir_all(&config.state_dir)
            .map_err(|e| NetworkError::io(format!("creating {}", config.state_dir.display()), e))?;
        let state_path = config.state_dir.join(STATE_FILE);
        let key_path = config.state_dir.join(WIREGUARD_KEY_FILE);
        let state: PersistedState = state_file::load(&state_path)?.unwrap_or_default();
        Ok(Networking {
            config,
            state_path,
            key_path,
            public_claims: RwLock::new(state.public.clone()),
            responder: SleepResponder::new(Ipv4Addr::UNSPECIFIED),
            state: Mutex::new(state),
        })
    }

    pub fn config(&self) -> &NetworkingConfig
    {
        &self.config
    }

    fn persist(&self, state: &PersistedState) -> Result<(), NetworkError>
    {
        state_file::save(&self.state_path, state)?;
        *self
            .public_claims
            .write()
            .unwrap_or_else(PoisonError::into_inner) = state.public.clone();
        Ok(())
    }

    async fn apply_public(&self, state: &mut PersistedState) -> Result<(), NetworkError>
    {
        self.responder.prepare(&mut state.public)?;
        if state.applied_public.as_ref() == Some(&state.public)
        {
            return Ok(());
        }
        self.persist(state)?;
        self.apply_nft(&nft::public_rules(&state.public), None)
            .await?;
        let desired = state.public.proxies();
        if !desired.is_empty() || !state.public.retired_proxies.is_empty()
        {
            let host = netlink::connect()?;
            for proxy in state.public.retired_proxies.difference(&desired)
            {
                netlink::remove_proxy_neighbour(&host, &proxy.interface, proxy.address).await?;
            }
            for proxy in &desired
            {
                write_sysctl(
                    &format!("/proc/sys/net/ipv4/conf/{}/proxy_arp", proxy.interface),
                    "1",
                )?;
                netlink::replace_proxy_neighbour(&host, &proxy.interface, proxy.address).await?;
            }
        }
        state.public.retired_proxies.clear();
        self.persist(state)?;
        self.responder.publish(&state.public);
        state.applied_public = Some(state.public.clone());
        Ok(())
    }

    async fn apply_nft(&self, ruleset: &Value, netns: Option<&File>) -> Result<(), NetworkError>
    {
        let input = serde_json::to_vec(ruleset).map_err(|e| NetworkError::UnexpectedOutput {
            command: "nft ruleset serialization".to_string(),
            reason: e.to_string(),
        })?;
        let args = ["-j", "-f", "-"].map(str::to_string);
        command::run(&self.config.nft_bin, &args, Some(&input), netns).await?;
        Ok(())
    }

    async fn wg(&self, args: &[String], stdin: Option<&[u8]>) -> Result<String, NetworkError>
    {
        command::run(&self.config.wg_bin, args, stdin, None).await
    }

    async fn apply_egress_limit(
        &self,
        host_ifname: &str,
        egress_mbit: u32,
    ) -> Result<(), NetworkError>
    {
        if egress_mbit == 0
        {
            let removal = command::run(
                &self.config.tc_bin,
                &tc::remove_ingress_qdisc_args(host_ifname),
                None,
                None,
            )
            .await;
            return match removal
            {
                Err(error) if !command::failed_with(&error, tc::is_missing_qdisc_error) =>
                {
                    Err(error)
                }
                _ => Ok(()),
            };
        }
        for args in tc::egress_limit_commands(host_ifname, egress_mbit)
        {
            command::run(&self.config.tc_bin, &args, None, None).await?;
        }
        Ok(())
    }

    async fn private_key(&self) -> Result<String, NetworkError>
    {
        let key = match fs::read_to_string(&self.key_path)
        {
            Ok(key) => key.trim().to_string(),
            Err(error) if error.kind() == ErrorKind::NotFound =>
            {
                let key = self
                    .wg(&["genkey".to_string()], None)
                    .await?
                    .trim()
                    .to_string();
                if !is_valid_key(&key)
                {
                    return Err(NetworkError::UnexpectedOutput {
                        command: "wg genkey".to_string(),
                        reason: "output is not a WireGuard key".to_string(),
                    });
                }
                state_file::write_atomically(&self.key_path, format!("{key}\n").as_bytes(), 0o600)?;
                info!(path = %self.key_path.display(), "generated WireGuard node key");
                key
            }
            Err(error) =>
            {
                return Err(NetworkError::io(
                    format!("reading {}", self.key_path.display()),
                    error,
                ));
            }
        };
        if !is_valid_key(&key)
        {
            return Err(NetworkError::UnexpectedOutput {
                command: format!("reading {}", self.key_path.display()),
                reason: "file does not contain a WireGuard key".to_string(),
            });
        }
        Ok(key)
    }

    async fn configure_wireguard(
        &self,
        host: &Handle,
        node: &NodeNetwork,
    ) -> Result<(), NetworkError>
    {
        let index = netlink::ensure_wireguard(host, wireguard::INTERFACE).await?;
        self.private_key().await?;
        let listing = self
            .wg(
                &["show", wireguard::INTERFACE, "peers"].map(str::to_string),
                None,
            )
            .await?;
        let current = wireguard::parse_peers(&listing);
        let args = wireguard::set_args(
            wireguard::INTERFACE,
            node.wireguard_listen_port,
            &self.key_path,
            &node.peers,
            &current,
        );
        self.wg(&args, None).await?;
        let addresses: Vec<IpPrefix> = node.wireguard_prefix()?.into_iter().collect();
        netlink::sync_addresses(host, index, &addresses).await?;
        netlink::set_link_up(host, index).await?;
        netlink::sync_static_routes(host, index, &wireguard::desired_routes(&node.peers)?).await?;
        debug!(peers = node.peers.len(), "WireGuard mesh synchronized");
        Ok(())
    }

    async fn attach_links(
        &self,
        spec: &InstanceNetworkSpec,
        subnet: Subnet,
        reuse_links: bool,
    ) -> Result<(), NetworkError>
    {
        let names = InterfaceNames::for_instance(&spec.instance_id);
        let netns_path = names.netns_path();
        let gateway = subnet.gateway();
        let guest_mac = parse_mac(&spec.guest_mac).ok_or_else(|| {
            NetworkError::invalid_spec(&spec.instance_id, "guest mac is malformed")
        })?;
        let host_mac = mac_with_prefix(0x01, spec.guest_ip);
        let namespace_mac = match spec.mode
        {
            AttachMode::Tap => mac_with_prefix(0x02, spec.guest_ip),
            AttachMode::Veth => guest_mac,
        };

        netns::create(&netns_path).await?;
        let netns_file = netns::open(&netns_path)?;
        let host = netlink::connect()?;
        let inside = netlink::connect_in(&netns_path).await?;

        let host_exists = netlink::link_index(&host, &names.host_veth)
            .await?
            .is_some();
        let peer_exists = netlink::link_index(&inside, &names.guest_veth)
            .await?
            .is_some();
        let fresh = !(reuse_links && host_exists && peer_exists);
        if fresh
        {
            netlink::delete_link(&host, &names.host_veth).await?;
            netlink::delete_link(&inside, &names.guest_veth).await?;
            netlink::add_veth_pair(
                &host,
                &netlink::VethPair {
                    host_name: &names.host_veth,
                    host_mac,
                    peer_name: &names.guest_veth,
                    peer_mac: namespace_mac,
                    peer_netns: netns_file.as_raw_fd(),
                },
            )
            .await?;
        }

        let host_index = netlink::require_link_index(&host, &names.host_veth).await?;
        netlink::set_link_up(&host, host_index).await?;
        write_sysctl(
            &format!("/proc/sys/net/ipv4/conf/{}/proxy_arp", names.host_veth),
            "1",
        )?;
        write_sysctl(
            &format!("/proc/sys/net/ipv4/neigh/{}/proxy_delay", names.host_veth),
            "0",
        )?;
        netlink::replace_host_route(&host, spec.guest_ip, host_index, Some(gateway)).await?;
        netlink::replace_permanent_neighbour(&host, host_index, spec.guest_ip, namespace_mac)
            .await?;

        let loopback = netlink::require_link_index(&inside, "lo").await?;
        netlink::set_link_up(&inside, loopback).await?;
        let peer_index = netlink::require_link_index(&inside, &names.guest_veth).await?;
        match spec.mode
        {
            AttachMode::Tap =>
            {
                netlink::set_link_up(&inside, peer_index).await?;
                netlink::replace_permanent_neighbour(&inside, peer_index, gateway, host_mac)
                    .await?;
                netlink::replace_default_route(&inside, gateway, peer_index, true).await?;
                if netlink::link_index(&inside, &names.tap).await?.is_none()
                {
                    let (tap, uid, gid) = (names.tap.clone(), spec.uid, spec.gid);
                    netns::run_inside(&netns_path, move || {
                        tun::create_persistent_tap(&tap, uid, gid)
                    })
                    .await?;
                }
                let tap_index = netlink::require_link_index(&inside, &names.tap).await?;
                netlink::set_link_up(&inside, tap_index).await?;
                let tap = names.tap.clone();
                netns::run_inside(&netns_path, move || {
                    write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
                    write_sysctl(&format!("/proc/sys/net/ipv4/conf/{tap}/proxy_arp"), "1")?;
                    write_sysctl(&format!("/proc/sys/net/ipv4/neigh/{tap}/proxy_delay"), "0")
                })
                .await?;
                netlink::replace_host_route(&inside, spec.guest_ip, tap_index, None).await?;
                netlink::replace_permanent_neighbour(&inside, tap_index, spec.guest_ip, guest_mac)
                    .await?;
                self.apply_nft(&nft::namespace_guard(spec), Some(&netns_file))
                    .await?;
            }
            AttachMode::Veth =>
            {
                if fresh
                {
                    let guest_prefix = IpPrefix {
                        addr: IpAddr::V4(spec.guest_ip),
                        len: subnet.prefix_len(),
                    };
                    netlink::replace_address(&inside, peer_index, guest_prefix).await?;
                    netlink::set_link_up(&inside, peer_index).await?;
                    netlink::replace_default_route(&inside, gateway, peer_index, false).await?;
                }
            }
        }
        Ok(())
    }

    async fn remove_instance(
        &self,
        state: &PersistedState,
        instance_id: &str,
    ) -> Result<(), NetworkError>
    {
        let names = InterfaceNames::for_instance(instance_id);
        let world = state.world_membership(instance_id);
        self.apply_nft(&nft::instance_removal(instance_id, world.as_ref()), None)
            .await?;
        match self
            .apply_nft(&nft::host_guard_removal(instance_id), None)
            .await
        {
            Err(error) if !command::failed_with(&error, nft::is_missing_object_error) =>
            {
                return Err(error);
            }
            _ =>
            {}
        }
        let netns_path = names.netns_path();
        if netns::exists(&netns_path)?
        {
            let inside = netlink::connect_in(&netns_path).await?;
            netlink::delete_link(&inside, &names.tap).await?;
            netlink::delete_link(&inside, &names.guest_veth).await?;
        }
        let host = netlink::connect()?;
        netlink::delete_link(&host, &names.host_veth).await?;
        netns::remove(&netns_path)
    }
}

fn write_sysctl(path: &str, value: &str) -> Result<(), NetworkError>
{
    fs::write(Path::new(path), value)
        .map_err(|e| NetworkError::io(format!("writing {value} to {path}"), e))
}

#[async_trait]
impl Network for Networking
{
    async fn configure_public(&self, config: &PublicIpv4Config) -> Result<(), NetworkError>
    {
        let mut state = self.state.lock().await;
        state.public.configure(config)?;
        self.apply_public(&mut state).await
    }

    fn validate_public_ipv4(&self, instance_id: &str, address: &str) -> Result<(), NetworkError>
    {
        self.public_claims
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .validate(instance_id, address)
    }

    async fn attach_public(&self, instance_id: &str, address: Ipv4Addr)
    -> Result<(), NetworkError>
    {
        let mut state = self.state.lock().await;
        let guest_ip = state
            .instances
            .get(instance_id)
            .ok_or_else(|| NetworkError::NotAttached(instance_id.to_string()))?
            .spec
            .guest_ip;
        state.public.attach(instance_id, address, guest_ip)?;
        self.apply_public(&mut state).await
    }

    async fn detach_public(&self, instance_id: &str) -> Result<(), NetworkError>
    {
        let mut state = self.state.lock().await;
        state.public.remove(instance_id);
        self.apply_public(&mut state).await
    }

    async fn set_public_mode(
        &self,
        instance_id: &str,
        mode: PublicIpMode,
    ) -> Result<(), NetworkError>
    {
        let mut state = self.state.lock().await;
        if let Some(binding) = state.public.bindings.get_mut(instance_id)
        {
            binding.mode = mode;
            self.apply_public(&mut state).await?;
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

    async fn configure_node(&self, node: &NodeNetwork) -> Result<(), NetworkError>
    {
        node.validate()?;
        let mut state = self.state.lock().await;
        ensure_subnet_change_allowed(state.node.as_ref(), !state.instances.is_empty(), node)?;
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
        let host = netlink::connect()?;
        let gateway_index = netlink::ensure_dummy(&host, GATEWAY_LINK).await?;
        let gateway = IpPrefix {
            addr: IpAddr::V4(node.subnet.gateway()),
            len: 32,
        };
        netlink::sync_addresses(&host, gateway_index, &[gateway]).await?;
        netlink::set_link_up(&host, gateway_index).await?;
        self.apply_nft(
            &nft::node_ruleset(node.subnet, self.config.uplink_ifname.as_deref()),
            None,
        )
        .await?;
        if node.wireguard_requested()
        {
            self.configure_wireguard(&host, node).await?;
        }
        else
        {
            netlink::delete_link(&host, wireguard::INTERFACE).await?;
        }
        state.node = Some(node.clone());
        self.persist(&state)?;
        self.apply_public(&mut state).await?;
        info!(subnet = %node.subnet, region = %node.region, "node network configured");
        Ok(())
    }

    async fn attach(&self, spec: &InstanceNetworkSpec) -> Result<NetworkAttachment, NetworkError>
    {
        let mut state = self.state.lock().await;
        let subnet = state
            .node
            .as_ref()
            .map(|node| node.subnet)
            .ok_or(NetworkError::NodeNotConfigured)?;
        spec.validate(subnet)?;
        spec.ensure_address_is_free(
            state
                .instances
                .values()
                .map(|record| (record.spec.instance_id.as_str(), record.spec.guest_ip)),
        )?;
        let names = InterfaceNames::for_instance(&spec.instance_id);
        if let Some(other) = state.instances.keys().find(|other| {
            *other != &spec.instance_id
                && InterfaceNames::for_instance(other).short_id == names.short_id
        })
        {
            return Err(NetworkError::invalid_spec(
                &spec.instance_id,
                format!("interface names collide with instance {other}"),
            ));
        }

        let previous = state.instances.get(&spec.instance_id).cloned();
        let reuse_links = previous
            .as_ref()
            .is_some_and(|record| record.complete && record.has_same_links(spec));
        if let Some(record) = &previous
            && !record.has_same_links(spec)
        {
            info!(instance_id = %spec.instance_id, "link parameters changed, rebuilding the attachment");
            self.remove_instance(&state, &spec.instance_id).await?;
        }
        let stale_world = previous
            .as_ref()
            .filter(|record| {
                record.has_same_links(spec)
                    && record.world_set() != world_set_name(&spec.world_id, &spec.instance_id)
            })
            .and_then(|_| state.world_membership(&spec.instance_id));

        state.instances.insert(
            spec.instance_id.clone(),
            InstanceRecord {
                spec: spec.clone(),
                complete: reuse_links,
            },
        );
        self.persist(&state)?;

        self.attach_links(spec, subnet, reuse_links).await?;
        self.apply_nft(&nft::instance_rules(spec), None).await?;
        if let Some(world) = stale_world
        {
            self.apply_nft(&nft::world_membership_removal(&world), None)
                .await?;
        }
        self.apply_egress_limit(&names.host_veth, spec.egress_mbit)
            .await?;

        if let Some(record) = state.instances.get_mut(&spec.instance_id)
        {
            record.complete = true;
        }
        if let Some(binding) = state.public.bindings.get_mut(&spec.instance_id)
        {
            binding.guest_ip = spec.guest_ip;
            self.apply_public(&mut state).await?;
        }
        self.persist(&state)?;
        info!(instance_id = %spec.instance_id, guest_ip = %spec.guest_ip, mode = ?spec.mode, "instance network attached");
        Ok(spec.attachment(subnet))
    }

    async fn detach(&self, instance_id: &str) -> Result<(), NetworkError>
    {
        let mut state = self.state.lock().await;
        state.public.remove(instance_id);
        self.apply_public(&mut state).await?;
        self.remove_instance(&state, instance_id).await?;
        if state.instances.remove(instance_id).is_some()
        {
            self.persist(&state)?;
        }
        info!(instance_id, "instance network detached");
        Ok(())
    }

    async fn counters(
        &self,
        attachment: &NetworkAttachment,
    ) -> Result<InterfaceCounters, NetworkError>
    {
        let host = netlink::connect()?;
        let link = netlink::link(&host, &attachment.host_ifname)
            .await?
            .ok_or_else(|| NetworkError::NotAttached(attachment.instance_id.clone()))?;
        let (host_rx, host_tx) =
            netlink::byte_counters(&link).ok_or_else(|| NetworkError::UnexpectedOutput {
                command: format!("netlink link stats for {}", attachment.host_ifname),
                reason: "no 64-bit statistics attribute".to_string(),
            })?;
        Ok(InterfaceCounters {
            rx_bytes: host_tx,
            tx_bytes: host_rx,
        })
    }

    async fn wireguard_public_key(&self) -> Result<Option<String>, NetworkError>
    {
        let _serialized = self.state.lock().await;
        let private_key = self.private_key().await?;
        let public_key = self
            .wg(
                &["pubkey".to_string()],
                Some(format!("{private_key}\n").as_bytes()),
            )
            .await?
            .trim()
            .to_string();
        if !is_valid_key(&public_key)
        {
            return Err(NetworkError::UnexpectedOutput {
                command: "wg pubkey".to_string(),
                reason: "output is not a WireGuard key".to_string(),
            });
        }
        Ok(Some(public_key))
    }
}
