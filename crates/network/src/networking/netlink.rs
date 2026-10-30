use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

use futures::TryStreamExt;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{InfoData, InfoVeth, LinkAttribute, LinkMessage};
use rtnetlink::packet_route::neighbour::NeighbourState;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope,
};
use rtnetlink::sys::protocols::NETLINK_ROUTE;
use rtnetlink::sys::{Socket, TokioSocket};
use rtnetlink::{
    Handle, LinkDummy, LinkMessageBuilder, LinkUnspec, LinkVeth, LinkWireguard, RouteMessageBuilder,
};

use super::netns;
use crate::error::NetworkError;
use crate::wireguard::IpPrefix;

pub(crate) fn netlink_error(context: impl Into<String>, error: rtnetlink::Error) -> NetworkError
{
    NetworkError::Netlink {
        context: context.into(),
        message: error.to_string(),
    }
}

fn is_errno(error: &rtnetlink::Error, errno: i32) -> bool
{
    matches!(error, rtnetlink::Error::NetlinkError(message) if message.raw_code() == -errno)
}

pub(crate) fn connect() -> Result<Handle, NetworkError>
{
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| NetworkError::io("opening a netlink socket", e))?;
    tokio::spawn(connection);
    Ok(handle)
}

pub(crate) async fn connect_in(netns_path: &Path) -> Result<Handle, NetworkError>
{
    let raw_fd: RawFd = netns::run_inside(netns_path, || {
        Socket::new(NETLINK_ROUTE)
            .map(IntoRawFd::into_raw_fd)
            .map_err(|e| NetworkError::io("opening a netlink socket", e))
    })
    .await?;
    // SAFETY: raw_fd was just released by a freshly created netlink socket and is owned by nothing else.
    let socket = unsafe { TokioSocket::from_raw_fd(raw_fd) };
    let (connection, handle, _) = rtnetlink::from_socket(socket);
    tokio::spawn(connection);
    Ok(handle)
}

pub(crate) async fn link(handle: &Handle, name: &str) -> Result<Option<LinkMessage>, NetworkError>
{
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await
    {
        Ok(link) => Ok(link),
        Err(e) if is_errno(&e, libc::ENODEV) => Ok(None),
        Err(e) => Err(netlink_error(format!("looking up link {name}"), e)),
    }
}

pub(crate) async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>, NetworkError>
{
    Ok(link(handle, name).await?.map(|link| link.header.index))
}

pub(crate) async fn require_link_index(handle: &Handle, name: &str) -> Result<u32, NetworkError>
{
    link_index(handle, name)
        .await?
        .ok_or_else(|| NetworkError::Netlink {
            context: format!("looking up link {name}"),
            message: "link does not exist".to_string(),
        })
}

pub(crate) fn byte_counters(link: &LinkMessage) -> Option<(u64, u64)>
{
    link.attributes.iter().find_map(|attribute| match attribute
    {
        LinkAttribute::Stats64(stats) => Some((stats.rx_bytes, stats.tx_bytes)),
        _ => None,
    })
}

pub(crate) async fn delete_link(handle: &Handle, name: &str) -> Result<(), NetworkError>
{
    let Some(index) = link_index(handle, name).await?
    else
    {
        return Ok(());
    };
    match handle.link().del(index).execute().await
    {
        Ok(()) => Ok(()),
        Err(e) if is_errno(&e, libc::ENODEV) => Ok(()),
        Err(e) => Err(netlink_error(format!("deleting link {name}"), e)),
    }
}

pub(crate) async fn set_link_up(handle: &Handle, index: u32) -> Result<(), NetworkError>
{
    handle
        .link()
        .set(LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
        .map_err(|e| netlink_error(format!("bringing up link {index}"), e))
}

pub(crate) struct VethPair<'a>
{
    pub host_name: &'a str,
    pub host_mac: [u8; 6],
    pub peer_name: &'a str,
    pub peer_mac: [u8; 6],
    pub peer_netns: RawFd,
}

pub(crate) async fn add_veth_pair(handle: &Handle, pair: &VethPair<'_>)
-> Result<(), NetworkError>
{
    let peer = LinkUnspec::new_with_name(pair.peer_name)
        .address(pair.peer_mac.to_vec())
        .setns_by_fd(pair.peer_netns)
        .build();
    let message = LinkMessageBuilder::<LinkVeth>::new_with_info_kind(
        rtnetlink::packet_route::link::InfoKind::Veth,
    )
    .name(pair.host_name.to_string())
    .address(pair.host_mac.to_vec())
    .set_info_data(InfoData::Veth(InfoVeth::Peer(peer)))
    .build();
    handle.link().add(message).execute().await.map_err(|e| {
        netlink_error(
            format!("creating veth pair {} / {}", pair.host_name, pair.peer_name),
            e,
        )
    })
}

pub(crate) async fn ensure_dummy(handle: &Handle, name: &str) -> Result<u32, NetworkError>
{
    if let Some(index) = link_index(handle, name).await?
    {
        return Ok(index);
    }
    handle
        .link()
        .add(LinkDummy::new(name).build())
        .execute()
        .await
        .map_err(|e| netlink_error(format!("creating dummy link {name}"), e))?;
    require_link_index(handle, name).await
}

pub(crate) async fn ensure_wireguard(handle: &Handle, name: &str) -> Result<u32, NetworkError>
{
    if let Some(index) = link_index(handle, name).await?
    {
        return Ok(index);
    }
    handle
        .link()
        .add(LinkWireguard::new(name).build())
        .execute()
        .await
        .map_err(|e| netlink_error(format!("creating wireguard link {name}"), e))?;
    require_link_index(handle, name).await
}

fn address_of(message: &AddressMessage) -> Option<IpAddr>
{
    let local = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute
        {
            AddressAttribute::Local(ip) => Some(*ip),
            _ => None,
        });
    local.or_else(|| {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute
            {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            })
    })
}

pub(crate) async fn sync_addresses(
    handle: &Handle,
    index: u32,
    desired: &[IpPrefix],
) -> Result<(), NetworkError>
{
    let existing: Vec<AddressMessage> = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await
        .map_err(|e| netlink_error(format!("listing addresses of link {index}"), e))?;
    for message in existing
    {
        let Some(ip) = address_of(&message)
        else
        {
            continue;
        };
        if ip.is_ipv6() && matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
        {
            continue;
        }
        let current = IpPrefix {
            addr: ip,
            len: message.header.prefix_len,
        };
        if !desired.contains(&current)
        {
            handle.address().del(message).execute().await.map_err(|e| {
                netlink_error(format!("removing address {current} from link {index}"), e)
            })?;
        }
    }
    for prefix in desired
    {
        replace_address(handle, index, *prefix).await?;
    }
    Ok(())
}

pub(crate) async fn replace_address(
    handle: &Handle,
    index: u32,
    prefix: IpPrefix,
) -> Result<(), NetworkError>
{
    handle
        .address()
        .add(index, prefix.addr, prefix.len)
        .replace()
        .execute()
        .await
        .map_err(|e| netlink_error(format!("assigning {prefix} to link {index}"), e))
}

pub(crate) async fn replace_host_route(
    handle: &Handle,
    destination: Ipv4Addr,
    index: u32,
    preferred_source: Option<Ipv4Addr>,
) -> Result<(), NetworkError>
{
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(destination, 32)
        .output_interface(index)
        .scope(RouteScope::Link)
        .protocol(RouteProtocol::Static);
    if let Some(source) = preferred_source
    {
        builder = builder.pref_source(source);
    }
    handle
        .route()
        .add(builder.build())
        .replace()
        .execute()
        .await
        .map_err(|e| netlink_error(format!("routing {destination}/32 via link {index}"), e))
}

pub(crate) async fn replace_default_route(
    handle: &Handle,
    gateway: Ipv4Addr,
    index: u32,
    onlink: bool,
) -> Result<(), NetworkError>
{
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .gateway(gateway)
        .output_interface(index)
        .protocol(RouteProtocol::Static);
    if onlink
    {
        builder = builder.onlink();
    }
    handle
        .route()
        .add(builder.build())
        .replace()
        .execute()
        .await
        .map_err(|e| netlink_error(format!("setting default route via {gateway}"), e))
}

pub(crate) async fn replace_permanent_neighbour(
    handle: &Handle,
    index: u32,
    ip: Ipv4Addr,
    mac: [u8; 6],
) -> Result<(), NetworkError>
{
    handle
        .neighbours()
        .add(index, IpAddr::V4(ip))
        .link_layer_address(&mac)
        .state(NeighbourState::Permanent)
        .replace()
        .execute()
        .await
        .map_err(|e| netlink_error(format!("pinning neighbour {ip} on link {index}"), e))
}

fn route_destination(route: &RouteMessage) -> Option<IpPrefix>
{
    route.attributes.iter().find_map(|attribute| match attribute
    {
        RouteAttribute::Destination(RouteAddress::Inet(v4)) => Some(IpPrefix {
            addr: IpAddr::V4(*v4),
            len: route.header.destination_prefix_length,
        }),
        RouteAttribute::Destination(RouteAddress::Inet6(v6)) => Some(IpPrefix {
            addr: IpAddr::V6(*v6),
            len: route.header.destination_prefix_length,
        }),
        _ => None,
    })
}

fn route_output_interface(route: &RouteMessage) -> Option<u32>
{
    route.attributes.iter().find_map(|attribute| match attribute
    {
        RouteAttribute::Oif(index) => Some(*index),
        _ => None,
    })
}

pub(crate) async fn sync_static_routes(
    handle: &Handle,
    index: u32,
    desired: &[IpPrefix],
) -> Result<(), NetworkError>
{
    let dumps = [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
    ];
    for dump in dumps
    {
        let routes: Vec<RouteMessage> = handle
            .route()
            .get(dump)
            .execute()
            .try_collect()
            .await
            .map_err(|e| netlink_error(format!("listing routes of link {index}"), e))?;
        for route in routes
        {
            if route_output_interface(&route) != Some(index)
                || route.header.protocol != RouteProtocol::Static
            {
                continue;
            }
            let keep =
                route_destination(&route).is_some_and(|destination| desired.contains(&destination));
            if !keep
            {
                handle.route().del(route).execute().await.map_err(|e| {
                    netlink_error(format!("removing a stale route from link {index}"), e)
                })?;
            }
        }
    }
    for prefix in desired
    {
        let message = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(prefix.addr, prefix.len)
            .map_err(|e| NetworkError::InvalidNodeNetwork(e.to_string()))?
            .output_interface(index)
            .scope(RouteScope::Link)
            .protocol(RouteProtocol::Static)
            .build();
        handle
            .route()
            .add(message)
            .replace()
            .execute()
            .await
            .map_err(|e| netlink_error(format!("routing {prefix} via link {index}"), e))?;
    }
    Ok(())
}
