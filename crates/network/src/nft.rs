use std::net::Ipv4Addr;

use serde_json::{Value, json};

use crate::instance::{AttachMode, InstanceNetworkSpec};
use crate::names::{InterfaceNames, stable_hash_hex};
use crate::subnet::Subnet;
use crate::wireguard;

pub const TABLE: &str = "quarry";
pub const INET: &str = "inet";
pub const NETDEV: &str = "netdev";
pub const HOST_IFNAME_PATTERN: &str = "qh-*";
pub const SPOOF_GUARD_MAP: &str = "spoof_guard";
pub const FROM_INSTANCE_MAP: &str = "from_instance";
pub const TO_INSTANCE_MAP: &str = "to_instance";
pub const INSTANCE_EGRESS_CHAIN: &str = "instance_egress";
pub const NAMESPACE_GUARD_CHAIN: &str = "guest";
pub const PREROUTING_PRIORITY: i32 = -300;
pub const FILTER_PRIORITY: i32 = 0;
pub const SRCNAT_PRIORITY: i32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldMembership
{
    pub set_name: String,
    pub guest_ip: Ipv4Addr,
    pub remove_set: bool,
}

pub fn world_key(world_id: &str, instance_id: &str) -> String
{
    if world_id.is_empty()
    {
        format!("instance:{instance_id}")
    }
    else
    {
        format!("world:{world_id}")
    }
}

pub fn world_set_name(world_id: &str, instance_id: &str) -> String
{
    format!(
        "world-{}",
        stable_hash_hex(&world_key(world_id, instance_id))
    )
}

pub fn guard_chain(names: &InterfaceNames) -> String
{
    format!("guard-{}", names.short_id)
}

pub fn forward_chain(names: &InterfaceNames) -> String
{
    format!("fwd-{}", names.short_id)
}

pub fn host_chain(names: &InterfaceNames) -> String
{
    format!("host-{}", names.short_id)
}

pub fn mac_chain(names: &InterfaceNames) -> String
{
    format!("mac-{}", names.short_id)
}

pub fn node_ruleset(subnet: Subnet, uplink_ifname: Option<&str>) -> Value
{
    let mut commands = inet_declarations();

    commands.extend(replaced_base_chain(
        INET,
        "prerouting",
        "filter",
        "prerouting",
        PREROUTING_PRIORITY,
        None,
    ));
    commands.push(rule(
        INET,
        "prerouting",
        vec![vmap("iifname", SPOOF_GUARD_MAP)],
    ));
    commands.push(rule(INET, "prerouting", vec![from_any_instance(), drop()]));

    commands.extend(replaced_base_chain(
        INET,
        "input",
        "filter",
        "input",
        FILTER_PRIORITY,
        None,
    ));
    commands.push(rule(
        INET,
        "input",
        vec![from_any_instance(), established(), accept()],
    ));
    commands.push(rule(INET, "input", vec![from_any_instance(), drop()]));

    commands.extend(replaced_base_chain(
        INET,
        "forward",
        "filter",
        "forward",
        FILTER_PRIORITY,
        None,
    ));
    commands.push(rule(
        INET,
        "forward",
        vec![vmap("iifname", FROM_INSTANCE_MAP)],
    ));
    commands.push(rule(INET, "forward", vec![from_any_instance(), drop()]));
    commands.push(rule(
        INET,
        "forward",
        vec![to_any_instance(), established(), accept()],
    ));
    commands.push(rule(INET, "forward", vec![to_any_instance(), drop()]));

    commands.extend(replaced_base_chain(
        INET,
        "output",
        "filter",
        "output",
        FILTER_PRIORITY,
        None,
    ));
    commands.push(rule(
        INET,
        "output",
        vec![to_any_instance(), established(), accept()],
    ));
    commands.push(rule(INET, "output", vec![vmap("oifname", TO_INSTANCE_MAP)]));
    commands.push(rule(INET, "output", vec![to_any_instance(), drop()]));

    commands.push(flush_chain(INET, INSTANCE_EGRESS_CHAIN));
    commands.push(rule(
        INET,
        INSTANCE_EGRESS_CHAIN,
        vec![compare("==", ip_field("daddr"), prefix(subnet)), drop()],
    ));
    commands.push(rule(
        INET,
        INSTANCE_EGRESS_CHAIN,
        vec![
            compare("==", meta("oifname"), json!(wireguard::INTERFACE)),
            drop(),
        ],
    ));
    commands.push(rule(
        INET,
        INSTANCE_EGRESS_CHAIN,
        vec![to_any_instance(), drop()],
    ));
    match uplink_ifname
    {
        Some(uplink) =>
        {
            commands.push(rule(
                INET,
                INSTANCE_EGRESS_CHAIN,
                vec![compare("==", meta("oifname"), json!(uplink)), accept()],
            ));
            commands.push(rule(INET, INSTANCE_EGRESS_CHAIN, vec![drop()]));
        }
        None => commands.push(rule(INET, INSTANCE_EGRESS_CHAIN, vec![accept()])),
    }

    commands.extend(replaced_base_chain(
        INET,
        "postrouting",
        "nat",
        "postrouting",
        SRCNAT_PRIORITY,
        None,
    ));
    let masquerade_match = match uplink_ifname
    {
        Some(uplink) => vec![
            compare("==", meta("oifname"), json!(uplink)),
            compare("==", ip_field("saddr"), prefix(subnet)),
        ],
        None => vec![
            compare("==", ip_field("saddr"), prefix(subnet)),
            compare("!=", ip_field("daddr"), prefix(subnet)),
            compare("!=", meta("oifname"), json!(wireguard::INTERFACE)),
        ],
    };
    let mut masquerade_rule = masquerade_match;
    masquerade_rule.push(json!({"masquerade": null}));
    commands.push(rule(INET, "postrouting", masquerade_rule));

    commands.push(add_table(NETDEV));
    batch(commands)
}

pub fn instance_rules(spec: &InstanceNetworkSpec) -> Value
{
    let names = InterfaceNames::for_instance(&spec.instance_id);
    let world_set = world_set_name(&spec.world_id, &spec.instance_id);
    let guard = guard_chain(&names);
    let forward = forward_chain(&names);
    let host = host_chain(&names);
    let mut commands = inet_declarations();

    commands.push(add_world_set(&world_set));
    commands.push(element(
        "add",
        INET,
        &world_set,
        json!([spec.guest_ip.to_string()]),
    ));

    commands.push(add_regular_chain(INET, &guard));
    commands.push(flush_chain(INET, &guard));
    commands.push(rule(
        INET,
        &guard,
        vec![compare("==", meta("nfproto"), json!("ipv6")), drop()],
    ));
    commands.push(rule(
        INET,
        &guard,
        vec![
            compare("!=", ip_field("saddr"), json!(spec.guest_ip.to_string())),
            drop(),
        ],
    ));
    commands.push(rule(INET, &guard, vec![accept()]));

    commands.push(add_regular_chain(INET, &forward));
    commands.push(flush_chain(INET, &forward));
    commands.push(rule(
        INET,
        &forward,
        vec![
            compare("==", ip_field("daddr"), json!(format!("@{world_set}"))),
            accept(),
        ],
    ));
    commands.push(rule(INET, &forward, vec![goto(INSTANCE_EGRESS_CHAIN)]));

    commands.push(add_regular_chain(INET, &host));
    commands.push(flush_chain(INET, &host));
    let ports = spec.exposed_ports();
    if !ports.is_empty()
    {
        for protocol in ["tcp", "udp"]
        {
            commands.push(rule(
                INET,
                &host,
                vec![
                    compare("==", payload(protocol, "dport"), json!({"set": ports})),
                    accept(),
                ],
            ));
        }
    }
    commands.push(rule(INET, &host, vec![drop()]));

    commands.push(element(
        "add",
        INET,
        SPOOF_GUARD_MAP,
        json!([[names.host_veth, {"goto": {"target": guard}}]]),
    ));
    commands.push(element(
        "add",
        INET,
        FROM_INSTANCE_MAP,
        json!([[names.host_veth, {"goto": {"target": forward}}]]),
    ));
    commands.push(element(
        "add",
        INET,
        TO_INSTANCE_MAP,
        json!([[names.host_veth, {"goto": {"target": host}}]]),
    ));

    if spec.mode == AttachMode::Veth
    {
        let mac = mac_chain(&names);
        commands.push(add_table(NETDEV));
        commands.extend(replaced_base_chain(
            NETDEV,
            &mac,
            "filter",
            "ingress",
            FILTER_PRIORITY,
            Some(&names.host_veth),
        ));
        commands.extend(guest_frame_rules(
            &mac,
            &spec.normalized_guest_mac(),
            spec.guest_ip,
        ));
    }
    batch(commands)
}

pub fn instance_removal(instance_id: &str, world: Option<&WorldMembership>) -> Value
{
    let names = InterfaceNames::for_instance(instance_id);
    let chains = [
        guard_chain(&names),
        forward_chain(&names),
        host_chain(&names),
    ];
    let mut commands = inet_declarations();
    for chain in &chains
    {
        commands.push(add_regular_chain(INET, chain));
    }
    for (map, chain) in [SPOOF_GUARD_MAP, FROM_INSTANCE_MAP, TO_INSTANCE_MAP]
        .into_iter()
        .zip(&chains)
    {
        commands.push(element(
            "add",
            INET,
            map,
            json!([[names.host_veth, {"goto": {"target": chain}}]]),
        ));
        commands.push(element("delete", INET, map, json!([names.host_veth])));
    }
    for chain in &chains
    {
        commands.push(flush_chain(INET, chain));
        commands
            .push(json!({"delete": {"chain": {"family": INET, "table": TABLE, "name": chain}}}));
    }
    if let Some(world) = world
    {
        commands.extend(world_membership_commands(world));
    }
    batch(commands)
}

pub fn world_membership_removal(world: &WorldMembership) -> Value
{
    let mut commands = inet_declarations();
    commands.extend(world_membership_commands(world));
    batch(commands)
}

fn world_membership_commands(world: &WorldMembership) -> Vec<Value>
{
    let ip = json!([world.guest_ip.to_string()]);
    let mut commands = vec![
        add_world_set(&world.set_name),
        element("add", INET, &world.set_name, ip.clone()),
        element("delete", INET, &world.set_name, ip),
    ];
    if world.remove_set
    {
        commands.push(
            json!({"delete": {"set": {"family": INET, "table": TABLE, "name": world.set_name}}}),
        );
    }
    commands
}

pub fn host_guard_removal(instance_id: &str) -> Value
{
    let names = InterfaceNames::for_instance(instance_id);
    batch(vec![json!({
        "delete": {"chain": {"family": NETDEV, "table": TABLE, "name": mac_chain(&names)}}
    })])
}

pub fn namespace_guard(spec: &InstanceNetworkSpec) -> Value
{
    let names = InterfaceNames::for_instance(&spec.instance_id);
    let mut commands = vec![add_table(NETDEV)];
    commands.extend(replaced_base_chain(
        NETDEV,
        NAMESPACE_GUARD_CHAIN,
        "filter",
        "ingress",
        FILTER_PRIORITY,
        Some(&names.tap),
    ));
    commands.extend(guest_frame_rules(
        NAMESPACE_GUARD_CHAIN,
        &spec.normalized_guest_mac(),
        spec.guest_ip,
    ));
    batch(commands)
}

pub fn is_missing_object_error(stderr: &str) -> bool
{
    stderr.contains("No such file or directory")
}

fn guest_frame_rules(chain: &str, guest_mac: &str, guest_ip: Ipv4Addr) -> Vec<Value>
{
    let from_guest_mac = compare("==", payload("ether", "saddr"), json!(guest_mac));
    vec![
        rule(
            NETDEV,
            chain,
            vec![
                from_guest_mac.clone(),
                compare("==", meta("protocol"), json!("ip")),
                compare("==", ip_field("saddr"), json!(guest_ip.to_string())),
                accept(),
            ],
        ),
        rule(
            NETDEV,
            chain,
            vec![
                from_guest_mac,
                compare("==", meta("protocol"), json!("arp")),
                compare("==", payload("arp", "saddr ether"), json!(guest_mac)),
                compare(
                    "==",
                    payload("arp", "saddr ip"),
                    json!(guest_ip.to_string()),
                ),
                accept(),
            ],
        ),
    ]
}

fn inet_declarations() -> Vec<Value>
{
    let mut commands = vec![add_table(INET)];
    for map in [SPOOF_GUARD_MAP, FROM_INSTANCE_MAP, TO_INSTANCE_MAP]
    {
        commands.push(json!({
            "add": {"map": {"family": INET, "table": TABLE, "name": map, "type": "ifname", "map": "verdict"}}
        }));
    }
    commands.push(add_regular_chain(INET, INSTANCE_EGRESS_CHAIN));
    commands
}

fn batch(commands: Vec<Value>) -> Value
{
    json!({"nftables": commands})
}

fn add_table(family: &str) -> Value
{
    json!({"add": {"table": {"family": family, "name": TABLE}}})
}

fn add_world_set(name: &str) -> Value
{
    json!({"add": {"set": {"family": INET, "table": TABLE, "name": name, "type": "ipv4_addr"}}})
}

fn add_regular_chain(family: &str, name: &str) -> Value
{
    json!({"add": {"chain": {"family": family, "table": TABLE, "name": name}}})
}

fn flush_chain(family: &str, name: &str) -> Value
{
    json!({"flush": {"chain": {"family": family, "table": TABLE, "name": name}}})
}

fn replaced_base_chain(
    family: &str,
    name: &str,
    chain_type: &str,
    hook: &str,
    priority: i32,
    device: Option<&str>,
) -> [Value; 2]
{
    let policy = match device
    {
        Some(_) => "drop",
        None => "accept",
    };
    let mut chain = json!({
        "family": family,
        "table": TABLE,
        "name": name,
        "type": chain_type,
        "hook": hook,
        "prio": priority,
        "policy": policy,
    });
    if let (Some(device), Some(object)) = (device, chain.as_object_mut())
    {
        object.insert("dev".to_string(), json!(device));
    }
    [json!({"add": {"chain": chain}}), flush_chain(family, name)]
}

fn element(operation: &str, family: &str, name: &str, elements: Value) -> Value
{
    json!({operation: {"element": {"family": family, "table": TABLE, "name": name, "elem": elements}}})
}

fn rule(family: &str, chain: &str, expressions: Vec<Value>) -> Value
{
    json!({"add": {"rule": {"family": family, "table": TABLE, "chain": chain, "expr": expressions}}})
}

fn compare(op: &str, left: Value, right: Value) -> Value
{
    json!({"match": {"op": op, "left": left, "right": right}})
}

fn meta(key: &str) -> Value
{
    json!({"meta": {"key": key}})
}

fn payload(protocol: &str, field: &str) -> Value
{
    json!({"payload": {"protocol": protocol, "field": field}})
}

fn ip_field(field: &str) -> Value
{
    payload("ip", field)
}

fn prefix(subnet: Subnet) -> Value
{
    json!({"prefix": {"addr": subnet.network().to_string(), "len": subnet.prefix_len()}})
}

fn vmap(key: &str, map: &str) -> Value
{
    json!({"vmap": {"key": meta(key), "data": format!("@{map}")}})
}

fn from_any_instance() -> Value
{
    compare("==", meta("iifname"), json!(HOST_IFNAME_PATTERN))
}

fn to_any_instance() -> Value
{
    compare("==", meta("oifname"), json!(HOST_IFNAME_PATTERN))
}

fn established() -> Value
{
    compare(
        "in",
        json!({"ct": {"key": "state"}}),
        json!(["established", "related"]),
    )
}

fn accept() -> Value
{
    json!({"accept": null})
}

fn drop() -> Value
{
    json!({"drop": null})
}

fn goto(target: &str) -> Value
{
    json!({"goto": {"target": target}})
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::ipam::guest_mac;

    fn subnet() -> Subnet
    {
        Subnet::parse("10.0.0.0/24").unwrap()
    }

    fn spec(id: &str, world: &str, last_octet: u8, mode: AttachMode) -> InstanceNetworkSpec
    {
        let ip = Ipv4Addr::new(10, 0, 0, last_octet);
        InstanceNetworkSpec {
            instance_id: id.to_string(),
            world_id: world.to_string(),
            guest_ip: ip,
            guest_mac: guest_mac(ip),
            egress_mbit: 50,
            ports: vec![25565, 25575],
            mode,
            uid: 10_000,
            gid: 10_000,
        }
    }

    fn commands(value: &Value) -> &Vec<Value>
    {
        value["nftables"].as_array().unwrap()
    }

    fn rules(value: &Value, family: &str, chain: &str) -> Vec<Vec<Value>>
    {
        commands(value)
            .iter()
            .filter_map(|command| command.get("add").and_then(|add| add.get("rule")))
            .filter(|rule| {
                rule["family"] == family && rule["chain"] == chain && rule["table"] == TABLE
            })
            .map(|rule| rule["expr"].as_array().unwrap().clone())
            .collect()
    }

    fn position(value: &Value, predicate: impl Fn(&Value) -> bool) -> usize
    {
        commands(value).iter().position(predicate).unwrap()
    }

    fn match_expr(op: &str, left: Value, right: Value) -> Value
    {
        json!({"match": {"op": op, "left": left, "right": right}})
    }

    #[test]
    fn node_ruleset_declares_table_maps_and_hooks()
    {
        let value = node_ruleset(subnet(), Some("eth0"));
        let all = commands(&value);
        assert_eq!(
            all[0],
            json!({"add": {"table": {"family": "inet", "name": "quarry"}}})
        );
        for map in [SPOOF_GUARD_MAP, FROM_INSTANCE_MAP, TO_INSTANCE_MAP]
        {
            assert!(all.contains(&json!({
                "add": {"map": {"family": "inet", "table": "quarry", "name": map, "type": "ifname", "map": "verdict"}}
            })));
        }
        for (name, chain_type, hook, prio) in [
            ("prerouting", "filter", "prerouting", -300),
            ("input", "filter", "input", 0),
            ("forward", "filter", "forward", 0),
            ("output", "filter", "output", 0),
            ("postrouting", "nat", "postrouting", 100),
        ]
        {
            let add = position(&value, |c| {
                c["add"]["chain"]["name"] == name && c["add"]["chain"]["family"] == "inet"
            });
            assert_eq!(all[add]["add"]["chain"]["type"], chain_type);
            assert_eq!(all[add]["add"]["chain"]["hook"], hook);
            assert_eq!(all[add]["add"]["chain"]["prio"], prio);
            assert_eq!(all[add]["add"]["chain"]["policy"], "accept");
            let flush = position(&value, |c| c["flush"]["chain"]["name"] == name);
            let first_rule = position(&value, |c| c["add"]["rule"]["chain"] == name);
            assert!(
                add < flush && flush < first_rule,
                "{name} must be flushed before its rules are re-added"
            );
        }
        assert!(all.contains(&json!({"add": {"table": {"family": "netdev", "name": "quarry"}}})));
    }

    #[test]
    fn node_ruleset_dispatches_instance_traffic_and_denies_unknown_interfaces()
    {
        let value = node_ruleset(subnet(), Some("eth0"));
        let from_instance = match_expr("==", json!({"meta": {"key": "iifname"}}), json!("qh-*"));
        let to_instance = match_expr("==", json!({"meta": {"key": "oifname"}}), json!("qh-*"));
        let established = match_expr(
            "in",
            json!({"ct": {"key": "state"}}),
            json!(["established", "related"]),
        );
        assert_eq!(
            rules(&value, "inet", "prerouting"),
            vec![
                vec![
                    json!({"vmap": {"key": {"meta": {"key": "iifname"}}, "data": "@spoof_guard"}})
                ],
                vec![from_instance.clone(), json!({"drop": null})],
            ]
        );
        assert_eq!(
            rules(&value, "inet", "forward"),
            vec![
                vec![
                    json!({"vmap": {"key": {"meta": {"key": "iifname"}}, "data": "@from_instance"}})
                ],
                vec![from_instance.clone(), json!({"drop": null})],
                vec![
                    to_instance.clone(),
                    established.clone(),
                    json!({"accept": null})
                ],
                vec![to_instance.clone(), json!({"drop": null})],
            ]
        );
        assert_eq!(
            rules(&value, "inet", "input"),
            vec![
                vec![
                    from_instance.clone(),
                    established.clone(),
                    json!({"accept": null})
                ],
                vec![from_instance, json!({"drop": null})],
            ]
        );
        assert_eq!(
            rules(&value, "inet", "output"),
            vec![
                vec![to_instance.clone(), established, json!({"accept": null})],
                vec![
                    json!({"vmap": {"key": {"meta": {"key": "oifname"}}, "data": "@to_instance"}})
                ],
                vec![to_instance, json!({"drop": null})],
            ]
        );
    }

    #[test]
    fn node_ruleset_denies_tenant_traffic_and_masquerades_on_the_uplink()
    {
        let value = node_ruleset(subnet(), Some("eth0"));
        let subnet_prefix = json!({"prefix": {"addr": "10.0.0.0", "len": 24}});
        let egress = rules(&value, "inet", INSTANCE_EGRESS_CHAIN);
        assert_eq!(
            egress[0],
            vec![
                match_expr(
                    "==",
                    json!({"payload": {"protocol": "ip", "field": "daddr"}}),
                    subnet_prefix.clone()
                ),
                json!({"drop": null}),
            ]
        );
        assert_eq!(
            egress[1],
            vec![
                match_expr(
                    "==",
                    json!({"meta": {"key": "oifname"}}),
                    json!("wg-quarry")
                ),
                json!({"drop": null}),
            ]
        );
        assert_eq!(
            egress.last().unwrap(),
            &vec![json!({"drop": null})],
            "with an uplink, egress anywhere else is denied"
        );
        assert!(egress.contains(&vec![
            match_expr("==", json!({"meta": {"key": "oifname"}}), json!("eth0")),
            json!({"accept": null}),
        ]));
        assert_eq!(
            rules(&value, "inet", "postrouting"),
            vec![vec![
                match_expr("==", json!({"meta": {"key": "oifname"}}), json!("eth0")),
                match_expr(
                    "==",
                    json!({"payload": {"protocol": "ip", "field": "saddr"}}),
                    subnet_prefix
                ),
                json!({"masquerade": null}),
            ]]
        );
    }

    #[test]
    fn node_ruleset_without_uplink_masquerades_everything_leaving_the_subnet()
    {
        let value = node_ruleset(subnet(), None);
        let subnet_prefix = json!({"prefix": {"addr": "10.0.0.0", "len": 24}});
        assert_eq!(
            rules(&value, "inet", "postrouting"),
            vec![vec![
                match_expr(
                    "==",
                    json!({"payload": {"protocol": "ip", "field": "saddr"}}),
                    subnet_prefix.clone()
                ),
                match_expr(
                    "!=",
                    json!({"payload": {"protocol": "ip", "field": "daddr"}}),
                    subnet_prefix
                ),
                match_expr(
                    "!=",
                    json!({"meta": {"key": "oifname"}}),
                    json!("wg-quarry")
                ),
                json!({"masquerade": null}),
            ]]
        );
        assert_eq!(
            rules(&value, "inet", INSTANCE_EGRESS_CHAIN).last().unwrap(),
            &vec![json!({"accept": null})]
        );
    }

    #[test]
    fn instance_rules_enforce_source_address()
    {
        let spec = spec("srv-1", "world-a", 5, AttachMode::Tap);
        let names = InterfaceNames::for_instance("srv-1");
        let value = instance_rules(&spec);
        let guard = guard_chain(&names);
        assert_eq!(
            rules(&value, "inet", &guard),
            vec![
                vec![
                    match_expr("==", json!({"meta": {"key": "nfproto"}}), json!("ipv6")),
                    json!({"drop": null}),
                ],
                vec![
                    match_expr(
                        "!=",
                        json!({"payload": {"protocol": "ip", "field": "saddr"}}),
                        json!("10.0.0.5")
                    ),
                    json!({"drop": null}),
                ],
                vec![json!({"accept": null})],
            ]
        );
        assert!(commands(&value).contains(&json!({
            "add": {"element": {"family": "inet", "table": "quarry", "name": "spoof_guard",
                "elem": [[names.host_veth, {"goto": {"target": guard}}]]}}
        })));
    }

    #[test]
    fn instance_rules_allow_same_world_then_fall_through_to_tenant_deny()
    {
        let spec = spec("srv-1", "world-a", 5, AttachMode::Tap);
        let names = InterfaceNames::for_instance("srv-1");
        let value = instance_rules(&spec);
        let world_set = world_set_name("world-a", "srv-1");
        assert!(commands(&value).contains(&json!({
            "add": {"set": {"family": "inet", "table": "quarry", "name": world_set, "type": "ipv4_addr"}}
        })));
        assert!(commands(&value).contains(&json!({
            "add": {"element": {"family": "inet", "table": "quarry", "name": world_set, "elem": ["10.0.0.5"]}}
        })));
        let forward = forward_chain(&names);
        assert_eq!(
            rules(&value, "inet", &forward),
            vec![
                vec![
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "ip", "field": "daddr"}}),
                        json!(format!("@{world_set}"))
                    ),
                    json!({"accept": null}),
                ],
                vec![json!({"goto": {"target": "instance_egress"}})],
            ]
        );
        assert!(commands(&value).contains(&json!({
            "add": {"element": {"family": "inet", "table": "quarry", "name": "from_instance",
                "elem": [[names.host_veth, {"goto": {"target": forward}}]]}}
        })));
    }

    #[test]
    fn instances_share_a_set_only_within_one_world()
    {
        assert_eq!(
            world_set_name("world-a", "srv-1"),
            world_set_name("world-a", "srv-2")
        );
        assert_ne!(
            world_set_name("world-a", "srv-1"),
            world_set_name("world-b", "srv-1")
        );
        assert_ne!(world_set_name("", "srv-1"), world_set_name("", "srv-2"));
        assert_ne!(
            world_set_name("", "srv-1"),
            world_set_name("srv-1", "srv-1")
        );
    }

    #[test]
    fn instance_rules_allow_host_to_declared_ports_only()
    {
        let mut spec = spec("srv-1", "world-a", 5, AttachMode::Tap);
        spec.ports = vec![25575, 25565, 25565];
        let names = InterfaceNames::for_instance("srv-1");
        let value = instance_rules(&spec);
        let host = host_chain(&names);
        assert_eq!(
            rules(&value, "inet", &host),
            vec![
                vec![
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "tcp", "field": "dport"}}),
                        json!({"set": [25565, 25575]})
                    ),
                    json!({"accept": null}),
                ],
                vec![
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "udp", "field": "dport"}}),
                        json!({"set": [25565, 25575]})
                    ),
                    json!({"accept": null}),
                ],
                vec![json!({"drop": null})],
            ]
        );
        spec.ports.clear();
        assert_eq!(
            rules(&instance_rules(&spec), "inet", &host),
            vec![vec![json!({"drop": null})]]
        );
    }

    #[test]
    fn instance_rules_flush_chains_before_adding_rules()
    {
        let spec = spec("srv-1", "world-a", 5, AttachMode::Veth);
        let names = InterfaceNames::for_instance("srv-1");
        let value = instance_rules(&spec);
        for chain in [
            guard_chain(&names),
            forward_chain(&names),
            host_chain(&names),
            mac_chain(&names),
        ]
        {
            let flush = position(&value, |c| c["flush"]["chain"]["name"] == chain.as_str());
            let first_rule = position(&value, |c| c["add"]["rule"]["chain"] == chain.as_str());
            assert!(flush < first_rule, "{chain}");
            assert_eq!(
                commands(&value)
                    .iter()
                    .filter(|c| c["flush"]["chain"]["name"] == chain.as_str())
                    .count(),
                1
            );
        }
    }

    #[test]
    fn veth_mode_checks_guest_mac_on_the_host_side_veth()
    {
        let spec = spec("srv-1", "world-a", 5, AttachMode::Veth);
        let names = InterfaceNames::for_instance("srv-1");
        let value = instance_rules(&spec);
        let mac = mac_chain(&names);
        let chain = position(&value, |c| c["add"]["chain"]["name"] == mac.as_str());
        let chain = &commands(&value)[chain]["add"]["chain"];
        assert_eq!(chain["family"], "netdev");
        assert_eq!(chain["hook"], "ingress");
        assert_eq!(chain["dev"], names.host_veth.as_str());
        assert_eq!(chain["policy"], "drop");
        assert_eq!(
            rules(&value, "netdev", &mac),
            vec![
                vec![
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "ether", "field": "saddr"}}),
                        json!("06:00:0a:00:00:05")
                    ),
                    match_expr("==", json!({"meta": {"key": "protocol"}}), json!("ip")),
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "ip", "field": "saddr"}}),
                        json!("10.0.0.5")
                    ),
                    json!({"accept": null}),
                ],
                vec![
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "ether", "field": "saddr"}}),
                        json!("06:00:0a:00:00:05")
                    ),
                    match_expr("==", json!({"meta": {"key": "protocol"}}), json!("arp")),
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "arp", "field": "saddr ether"}}),
                        json!("06:00:0a:00:00:05")
                    ),
                    match_expr(
                        "==",
                        json!({"payload": {"protocol": "arp", "field": "saddr ip"}}),
                        json!("10.0.0.5")
                    ),
                    json!({"accept": null}),
                ],
            ]
        );
        let tap = spec_with_mode(AttachMode::Tap);
        assert!(rules(&instance_rules(&tap), "netdev", &mac).is_empty());
    }

    fn spec_with_mode(mode: AttachMode) -> InstanceNetworkSpec
    {
        spec("srv-1", "world-a", 5, mode)
    }

    #[test]
    fn tap_mode_checks_guest_mac_on_the_tap_inside_the_namespace()
    {
        let spec = spec_with_mode(AttachMode::Tap);
        let names = InterfaceNames::for_instance("srv-1");
        let value = namespace_guard(&spec);
        let chain = position(&value, |c| {
            c["add"]["chain"]["name"] == NAMESPACE_GUARD_CHAIN
        });
        let chain = &commands(&value)[chain]["add"]["chain"];
        assert_eq!(chain["family"], "netdev");
        assert_eq!(chain["dev"], names.tap.as_str());
        assert_eq!(chain["policy"], "drop");
        let guest_rules = rules(&value, "netdev", NAMESPACE_GUARD_CHAIN);
        assert_eq!(guest_rules.len(), 2);
        assert!(guest_rules.iter().all(|rule| rule[0]
            == match_expr(
                "==",
                json!({"payload": {"protocol": "ether", "field": "saddr"}}),
                json!("06:00:0a:00:00:05")
            )));
    }

    #[test]
    fn removal_is_self_contained_and_ordered()
    {
        let names = InterfaceNames::for_instance("srv-1");
        let world = WorldMembership {
            set_name: world_set_name("world-a", "srv-1"),
            guest_ip: Ipv4Addr::new(10, 0, 0, 5),
            remove_set: true,
        };
        let value = instance_removal("srv-1", Some(&world));
        for (map, chain) in [
            (SPOOF_GUARD_MAP, guard_chain(&names)),
            (FROM_INSTANCE_MAP, forward_chain(&names)),
            (TO_INSTANCE_MAP, host_chain(&names)),
        ]
        {
            let declared = position(&value, |c| c["add"]["chain"]["name"] == chain.as_str());
            let element_added = position(&value, |c| c["add"]["element"]["name"] == map);
            let element_deleted = position(&value, |c| {
                c["delete"]["element"]["name"] == map
                    && c["delete"]["element"]["elem"] == json!([names.host_veth])
            });
            let deleted = position(&value, |c| c["delete"]["chain"]["name"] == chain.as_str());
            assert!(
                declared < element_added
                    && element_added < element_deleted
                    && element_deleted < deleted
            );
        }
        let chain_deleted = position(&value, |c| {
            c["delete"]["chain"]["name"] == forward_chain(&names).as_str()
        });
        let element_deleted = position(&value, |c| {
            c["delete"]["element"]["name"] == world.set_name.as_str()
                && c["delete"]["element"]["elem"] == json!(["10.0.0.5"])
        });
        let set_deleted = position(&value, |c| {
            c["delete"]["set"]["name"] == world.set_name.as_str()
        });
        assert!(chain_deleted < element_deleted && element_deleted < set_deleted);

        let kept = WorldMembership {
            remove_set: false,
            ..world.clone()
        };
        let value = instance_removal("srv-1", Some(&kept));
        assert!(
            !commands(&value)
                .iter()
                .any(|c| c.get("delete").and_then(|d| d.get("set")).is_some())
        );
    }

    #[test]
    fn world_membership_removal_drops_only_the_address_unless_the_set_is_unused()
    {
        let world = WorldMembership {
            set_name: world_set_name("world-a", "srv-1"),
            guest_ip: Ipv4Addr::new(10, 0, 0, 5),
            remove_set: false,
        };
        let value = world_membership_removal(&world);
        assert!(commands(&value).contains(&json!({
            "delete": {"element": {"family": "inet", "table": "quarry", "name": world.set_name, "elem": ["10.0.0.5"]}}
        })));
        assert!(
            !commands(&value)
                .iter()
                .any(|c| c.get("delete").and_then(|d| d.get("set")).is_some())
        );
        let unused = WorldMembership {
            remove_set: true,
            ..world
        };
        assert!(
            commands(&world_membership_removal(&unused)).contains(&json!({
                "delete": {"set": {"family": "inet", "table": "quarry", "name": unused.set_name}}
            }))
        );
    }

    #[test]
    fn host_guard_removal_targets_the_netdev_chain()
    {
        let names = InterfaceNames::for_instance("srv-1");
        assert_eq!(
            host_guard_removal("srv-1"),
            json!({"nftables": [{"delete": {"chain": {"family": "netdev", "table": "quarry", "name": mac_chain(&names)}}}]})
        );
    }
}
