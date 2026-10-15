//! The machine's network, as `/padd` and the `/network/*` routes report it:
//! the kernel's routing tables (`/proc/net/route`, `/proc/net/ipv6_route`),
//! the interface addresses and `/sys/class/net`. FTL asks netlink for the
//! same data, so the few fields only netlink carries (a route's protocol, an
//! address's flags and lifetimes) are neutral or left out. All of it blocks,
//! so call it from `spawn_blocking`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::dto::network::{
    GatewayEntry, InterfaceAddress, InterfaceEntry, InterfaceStats, RouteEntry,
};
use crate::dto::padd::{PaddByteCount, PaddIface, PaddIfaceV4, PaddIfaceV6};

/// `RTF_*` of `<linux/route.h>` and `<linux/ipv6_route.h>`.
const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;
const RTF_ANYCAST: u32 = 0x0010_0000;
const RTF_LOCAL: u32 = 0x8000_0000;

/// `RT_TABLE_MAIN` and `RT_TABLE_LOCAL`.
const TABLE_MAIN: u32 = 254;
const TABLE_LOCAL: u32 = 255;

/// `IFF_*` of `<linux/if.h>` with FTL's names, in FTL's order
/// (netlink_consts.h iff_flags).
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;
const IFF_DORMANT: u32 = 0x2_0000;
const IFF_NAMES: [(u32, &str); 19] = [
    (IFF_UP, "up"),
    (0x2, "broadcast"),
    (0x4, "debug"),
    (0x8, "loopback"),
    (0x10, "pointopoint"),
    (0x20, "notrailers"),
    (IFF_RUNNING, "running"),
    (0x80, "noarp"),
    (0x100, "promisc"),
    (0x200, "allmulti"),
    (0x400, "master"),
    (0x800, "slave"),
    (0x1000, "multicast"),
    (0x2000, "portsel"),
    (0x4000, "automedia"),
    (0x8000, "dynamic"),
    (IFF_LOWER_UP, "lower_up"),
    (IFF_DORMANT, "dormant"),
    (0x4_0000, "echo"),
];

/// `ARPHRD_*` of `<linux/if_arp.h>` with FTL's names (netlink_consts.h
/// iflatypes; 513 is both CISCO and HDLC, and FTL names it `cisco`).
const LINK_TYPES: &[(i64, &str)] = &[
    (0, "netrom"),
    (1, "ether"),
    (2, "eether"),
    (3, "ax25"),
    (4, "pronet"),
    (5, "chaos"),
    (6, "ieee802"),
    (7, "arcnet"),
    (8, "appletlk"),
    (15, "dlci"),
    (19, "atm"),
    (23, "metricom"),
    (24, "ieee1394"),
    (27, "eui64"),
    (32, "infiniband"),
    (256, "slip"),
    (257, "cslip"),
    (258, "slip6"),
    (259, "cslip6"),
    (260, "rsrvd"),
    (264, "adapt"),
    (270, "rose"),
    (271, "x25"),
    (272, "hwx25"),
    (280, "can"),
    (290, "mctp"),
    (512, "ppp"),
    (513, "cisco"),
    (516, "lapb"),
    (517, "ddcmp"),
    (518, "rawhdlc"),
    (519, "rawip"),
    (768, "tunnel"),
    (769, "tunnel6"),
    (770, "frad"),
    (771, "skip"),
    (772, "loopback"),
    (773, "localtlk"),
    (774, "fddi"),
    (775, "bif"),
    (776, "sit"),
    (777, "ipddp"),
    (778, "ipgre"),
    (779, "pimreg"),
    (780, "hippi"),
    (781, "ash"),
    (782, "econet"),
    (783, "irda"),
    (784, "fcpp"),
    (785, "fcal"),
    (786, "fcpl"),
    (787, "fcfabric"),
    (800, "ieee802_tr"),
    (801, "ieee80211"),
    (802, "ieee80211_prism"),
    (803, "ieee80211_radiotap"),
    (804, "ieee802154"),
    (805, "ieee802154_monitor"),
    (820, "phonet"),
    (821, "phonet_pipe"),
    (822, "caif"),
    (823, "ip6gre"),
    (824, "netlink"),
    (825, "6lowpan"),
    (826, "vsockmon"),
    (0xFFFF, "void"),
    (0xFFFE, "none"),
];

/// A row of `/proc/net/route` or `/proc/net/ipv6_route`.
#[derive(Debug, PartialEq)]
struct ProcRoute {
    interface: String,
    destination: IpAddr,
    prefix_len: u8,
    gateway: Option<IpAddr>,
    flags: u32,
    metric: u32,
}

impl ProcRoute {
    fn is_default(&self) -> bool {
        self.prefix_len == 0 && self.destination.is_unspecified()
    }
}

/// A default route: the interface it leaves through and its next hop.
#[derive(Debug, PartialEq)]
struct DefaultRoute {
    interface: String,
    gateway: Option<IpAddr>,
}

impl From<ProcRoute> for DefaultRoute {
    fn from(route: ProcRoute) -> Self {
        Self {
            interface: route.interface,
            gateway: route.gateway,
        }
    }
}

/// An interface address as getifaddrs reports it.
struct IfAddr {
    interface: String,
    address: IpAddr,
    prefix_len: u8,
    broadcast: Option<IpAddr>,
}

/// The IPv4 and IPv6 default-route interfaces, as padd.c describes them.
pub(crate) fn read_default_interfaces() -> PaddIface {
    let route_v4 = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|table| default_route_v4(&table));
    let route_v6 = std::fs::read_to_string("/proc/net/ipv6_route")
        .ok()
        .and_then(|table| default_route_v6(&table));
    let addresses = interface_addresses();

    let name_v4 = route_v4.as_ref().map(|route| route.interface.clone());
    // padd.c: without an IPv6 default route, the IPv6 side describes the
    // IPv4 interface.
    let name_v6 = route_v6
        .as_ref()
        .map(|route| route.interface.clone())
        .or_else(|| name_v4.clone());

    let addrs_v4 = addresses_of(&addresses, name_v4.as_deref(), IpAddr::is_ipv4);
    let addrs_v6 = addresses_of(&addresses, name_v6.as_deref(), IpAddr::is_ipv6);
    let counter = |name: &str| {
        name_v4
            .as_deref()
            .and_then(|interface| read_byte_counter(interface, name))
    };

    PaddIface {
        v4: PaddIfaceV4 {
            addr: addrs_v4.first().map(ToString::to_string),
            rx_bytes: counter("rx_bytes"),
            tx_bytes: counter("tx_bytes"),
            num_addrs: addrs_v4.len() as u64,
            name: name_v4,
            gw_addr: gateway_of(route_v4),
        },
        v6: PaddIfaceV6 {
            addr: addrs_v6.first().map(ToString::to_string),
            num_addrs: addrs_v6.len() as u64,
            name: name_v6,
            gw_addr: gateway_of(route_v6),
        },
    }
}

fn gateway_of(route: Option<DefaultRoute>) -> Option<String> {
    route?.gateway.map(|gateway| gateway.to_string())
}

fn addresses_of<'a>(
    addresses: &'a [IfAddr],
    interface: Option<&str>,
    family: fn(&IpAddr) -> bool,
) -> Vec<&'a IpAddr> {
    let Some(interface) = interface else {
        return Vec::new();
    };
    addresses
        .iter()
        .filter(|addr| addr.interface == interface && family(&addr.address))
        .map(|addr| &addr.address)
        .collect()
}

/// The rows of `/proc/net/route`: interface, destination, gateway, flags,
/// refcount, use, metric, mask, ... Addresses are the network-order bytes
/// printed as a host-order number; the metric is decimal.
fn parse_routes_v4(table: &str) -> Vec<ProcRoute> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [interface, destination, gateway, flags, _, _, metric, mask, ..] = fields[..]
            else {
                return None;
            };
            let hex = |field: &str| u32::from_str_radix(field, 16).ok();
            let address = |raw: u32| IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()));
            let gateway = hex(gateway)?;
            Some(ProcRoute {
                interface: interface.to_string(),
                destination: address(hex(destination)?),
                prefix_len: hex(mask)?.count_ones() as u8,
                gateway: (gateway != 0).then(|| address(gateway)),
                flags: hex(flags)?,
                metric: metric.parse().ok()?,
            })
        })
        .collect()
}

/// The rows of `/proc/net/ipv6_route`: destination, prefix length, source,
/// source prefix length, next hop, metric, refcount, use, flags, interface,
/// all in hex.
fn parse_routes_v6(table: &str) -> Vec<ProcRoute> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [destination, prefix_len, _, _, next_hop, metric, _, _, flags, interface] =
                fields[..]
            else {
                return None;
            };
            let next_hop = u128::from_str_radix(next_hop, 16).ok()?;
            Some(ProcRoute {
                interface: interface.to_string(),
                destination: IpAddr::V6(Ipv6Addr::from(
                    u128::from_str_radix(destination, 16).ok()?,
                )),
                prefix_len: u8::from_str_radix(prefix_len, 16).ok()?,
                gateway: (next_hop != 0).then(|| IpAddr::V6(Ipv6Addr::from(next_hop))),
                flags: u32::from_str_radix(flags, 16).ok()?,
                metric: u32::from_str_radix(metric, 16).ok()?,
            })
        })
        .collect()
}

/// First up route of `/proc/net/route` with a zero destination and mask.
fn default_route_v4(table: &str) -> Option<DefaultRoute> {
    parse_routes_v4(table)
        .into_iter()
        .find(|route| route.is_default() && route.flags & RTF_UP != 0)
        .map(DefaultRoute::from)
}

/// First up, non-reject `::/0` route of `/proc/net/ipv6_route`.
fn default_route_v6(table: &str) -> Option<DefaultRoute> {
    parse_routes_v6(table)
        .into_iter()
        .find(|route| {
            route.is_default() && route.flags & RTF_UP != 0 && route.flags & RTF_REJECT == 0
        })
        .map(DefaultRoute::from)
}

/// Every route of the kernel's tables, as FTL lists them (netlink.c
/// nlparsemsg_route). `/proc/net/route` holds only the IPv4 main table, so
/// the IPv4 local and broadcast routes netlink also reports are missing.
pub(crate) fn read_routes() -> Vec<RouteEntry> {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let mut carrier = HashMap::new();
    route_entries(
        &parse_routes_v4(&read("/proc/net/route")),
        &parse_routes_v6(&read("/proc/net/ipv6_route")),
        |interface| {
            *carrier.entry(interface.to_string()).or_insert_with(|| {
                read_carrier(Path::new("/sys/class/net").join(interface).as_path())
            })
        },
    )
}

fn route_entries(
    v4: &[ProcRoute],
    v6: &[ProcRoute],
    mut has_carrier: impl FnMut(&str) -> bool,
) -> Vec<RouteEntry> {
    let v4 = v4.iter().map(|route| {
        let route_type = if route.flags & RTF_REJECT != 0 {
            "unreachable"
        } else {
            "unicast"
        };
        (
            route,
            TABLE_MAIN,
            route_type,
            (route.metric != 0).then_some(route.metric),
            None,
        )
    });
    // The kernel prints its `::/0` reject placeholders, which netlink does
    // not list.
    let v6 = v6
        .iter()
        .filter(|route| !(route.is_default() && route.flags & RTF_REJECT != 0))
        .map(|route| {
            let multicast = matches!(route.destination, IpAddr::V6(dst) if dst.is_multicast());
            let (table, route_type) = if route.flags & RTF_LOCAL != 0 {
                (TABLE_LOCAL, "local")
            } else if route.flags & RTF_ANYCAST != 0 {
                (TABLE_LOCAL, "anycast")
            } else if multicast {
                (TABLE_LOCAL, "multicast")
            } else if route.flags & RTF_REJECT != 0 {
                (TABLE_MAIN, "unreachable")
            } else {
                (TABLE_MAIN, "unicast")
            };
            (route, table, route_type, Some(route.metric), Some(0))
        });

    v4.chain(v6)
        .map(|(route, table, route_type, priority, pref)| {
            let link_down = route_type != "local" && !has_carrier(&route.interface);
            RouteEntry {
                table,
                family: family_name(route.destination),
                protocol: "unspec",
                scope: route_scope(route, route_type),
                route_type,
                flags: if link_down {
                    vec!["linkdown"]
                } else {
                    Vec::new()
                },
                dst: if route.is_default() {
                    "default".to_string()
                } else {
                    route.destination.to_string()
                },
                gateway: route.gateway.map(|gateway| gateway.to_string()),
                oif: route.interface.clone(),
                priority,
                pref,
            }
        })
        .collect()
}

/// IPv4 routes through a gateway reach the universe and direct ones the
/// link; netlink reports every IPv6 route with universe scope.
fn route_scope(route: &ProcRoute, route_type: &str) -> &'static str {
    match route.destination {
        IpAddr::V6(_) => "universe",
        IpAddr::V4(_) if route_type == "local" => "host",
        IpAddr::V4(_) if route.gateway.is_some() => "universe",
        IpAddr::V4(_) => "link",
    }
}

/// The default routes with their interface's addresses (network.c
/// get_gateway).
pub(crate) fn gateways(routes: &[RouteEntry]) -> Vec<GatewayEntry> {
    let addresses = interface_addresses();
    routes
        .iter()
        .filter(|route| route.dst == "default")
        .map(|route| GatewayEntry {
            family: route.family,
            interface: route.oif.clone(),
            address: route.gateway.clone(),
            local: addresses
                .iter()
                .filter(|addr| {
                    addr.interface == route.oif && family_name(addr.address) == route.family
                })
                .map(|addr| addr.address.to_string())
                .collect(),
        })
        .collect()
}

/// Every interface with its addresses, in index order as netlink lists
/// them (netlink.c nlparsemsg_link, nlparsemsg_address).
pub(crate) fn read_interfaces() -> Vec<InterfaceEntry> {
    read_interfaces_at(Path::new("/sys/class/net"), &interface_addresses())
}

fn read_interfaces_at(root: &Path, addresses: &[IfAddr]) -> Vec<InterfaceEntry> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut links: Vec<(i64, String)> = entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            let index = read_number(&root.join(&name).join("ifindex")).unwrap_or(i64::MAX);
            Some((index, name))
        })
        .collect();
    links.sort();
    links
        .into_iter()
        .map(|(_, name)| read_interface(&root.join(&name), name, addresses))
        .collect()
}

fn read_interface(dir: &Path, name: String, addresses: &[IfAddr]) -> InterfaceEntry {
    let read = |file: &str| {
        std::fs::read_to_string(dir.join(file))
            .ok()
            .map(|value| value.trim().to_string())
    };
    let state = read("operstate").unwrap_or_else(|| "unknown".to_string());
    let carrier = read_carrier(dir);
    let is_mac = read_number(&dir.join("addr_len")) == Some(6);
    let counter = |file: &str| {
        scale_bytes(read_number(&dir.join("statistics").join(file)).unwrap_or(0) as u64)
    };

    // `flags` holds the configured bits; the kernel adds running, lower_up
    // and dormant from the link state (dev_get_flags).
    let mut flags = read("flags")
        .and_then(|flags| u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    if flags & IFF_UP != 0 {
        if state == "up" || state == "unknown" {
            flags |= IFF_RUNNING;
        }
        if carrier {
            flags |= IFF_LOWER_UP;
        }
        if state == "dormant" {
            flags |= IFF_DORMANT;
        }
    }

    InterfaceEntry {
        speed: read_number(&dir.join("speed")).filter(|speed| *speed > -1),
        link_type: read_number(&dir.join("type")).and_then(|kind| {
            LINK_TYPES
                .iter()
                .find(|(value, _)| *value == kind)
                .map(|(_, name)| *name)
        }),
        flags: IFF_NAMES
            .iter()
            .filter(|(bit, _)| flags & bit != 0)
            .map(|(_, name)| *name)
            .collect(),
        state: if state == "lowerlayerdown" {
            "lower_layer_down".to_string()
        } else {
            state
        },
        carrier,
        proto_down: read("proto_down").as_deref() == Some("1"),
        address: read("address").filter(|_| is_mac),
        broadcast: read("broadcast").filter(|_| is_mac),
        stats: InterfaceStats {
            rx_bytes: counter("rx_bytes"),
            tx_bytes: counter("tx_bytes"),
            bits: 64,
        },
        addresses: addresses
            .iter()
            .filter(|addr| addr.interface == name)
            .map(interface_address)
            .collect(),
        name,
    }
}

fn interface_address(addr: &IfAddr) -> InterfaceAddress {
    let address = addr.address.to_string();
    let kind = address_type(addr.address);
    let is_v4 = addr.address.is_ipv4();
    InterfaceAddress {
        family: family_name(addr.address),
        scope: address_scope(addr.address),
        flags: Vec::new(),
        prefixlen: addr.prefix_len,
        local: is_v4.then(|| address.clone()),
        local_type: is_v4.then_some(kind),
        broadcast: addr.broadcast.map(|broadcast| broadcast.to_string()),
        broadcast_type: addr.broadcast.map(address_type),
        label: is_v4.then(|| addr.interface.clone()),
        address,
        address_type: kind,
    }
}

fn family_name(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "inet",
        IpAddr::V6(_) => "inet6",
    }
}

/// The scope the kernel gives an address of this kind.
fn address_scope(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(v4) if v4.is_loopback() => "host",
        IpAddr::V4(v4) if v4.is_link_local() => "link",
        IpAddr::V6(v6) if v6.is_loopback() => "host",
        IpAddr::V6(v6) if v6.is_unicast_link_local() => "link",
        _ => "universe",
    }
}

/// FTL's address classes (netlink.c nlparsemsg_address); `private` is
/// dnsmasq's private_net, which includes CG-NAT, so FTL's own CG-NAT branch
/// never applies.
fn address_type(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(v4) => {
            let bits = v4.to_bits();
            let private = [
                (0xFF00_0000, 0x0A00_0000),
                (0xFFC0_0000, 0x6440_0000),
                (0xFFF0_0000, 0xAC10_0000),
                (0xFFFF_0000, 0xC0A8_0000),
                (0xFFFF_0000, 0xA9FE_0000),
                (0xFFFF_FF00, 0xC000_0200),
                (0xFFFF_FF00, 0xC633_6400),
                (0xFFFF_FF00, 0xCB00_7100),
                (0xFFFF_FFFF, 0xFFFF_FFFF),
            ]
            .iter()
            .any(|(mask, net)| bits & mask == *net);
            if v4.is_unspecified() {
                "unspecified"
            } else if v4.octets()[0] == 127 {
                "loopback"
            } else if v4.is_multicast() {
                "multicast"
            } else if private {
                "private"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            let segments = v6.segments();
            if v6.is_unspecified() {
                "unspecified"
            } else if v6.is_loopback() {
                "loopback"
            } else if v6.is_multicast() {
                "multicast"
            } else if v6.is_unicast_link_local() {
                "link-local (LL)"
            } else if segments[0] & 0xffc0 == 0xfec0 {
                "site-local (ULA)"
            } else if v6.to_ipv4_mapped().is_some() {
                "IPv4-mapped"
            } else if segments[..6] == [0; 6]
                && ((u32::from(segments[6]) << 16) | u32::from(segments[7])) > 1
            {
                "IPv4-compatible"
            } else if bytes[0] & 0x70 == 0x20 {
                "global (GUA)"
            } else if bytes[0] & 0xfe == 0xfc {
                "site-local (ULA)"
            } else {
                "unknown"
            }
        }
    }
}

/// Whether the link has a carrier; reading it fails on a link that is down.
fn read_carrier(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("carrier")).is_ok_and(|carrier| carrier.trim() == "1")
}

fn read_number(path: &Path) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// An interface counter, scaled as FTL prints it.
fn read_byte_counter(interface: &str, counter: &str) -> Option<PaddByteCount> {
    let path = format!("/sys/class/net/{interface}/statistics/{counter}");
    let bytes: u64 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    Some(scale_bytes(bytes))
}

/// Divides by 1024 until the value is at most 1024 (log.c format_memory_size).
fn scale_bytes(bytes: u64) -> PaddByteCount {
    const PREFIXES: [&str; 10] = ["", "k", "M", "G", "T", "P", "E", "Z", "Y", "R"];
    let mut value = bytes as f64;
    let mut prefix = 0;
    while value > 1024.0 && prefix < PREFIXES.len() - 1 {
        value /= 1024.0;
        prefix += 1;
    }
    PaddByteCount {
        value,
        unit: PREFIXES[prefix].to_string(),
    }
}

/// Every interface address, in the kernel's order.
#[cfg(target_os = "linux")]
fn interface_addresses() -> Vec<IfAddr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs only writes the head of the list it allocates.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list getifaddrs returned, which
        // stays alive until the freeifaddrs below.
        let entry = unsafe { &*cursor };
        // SAFETY: `ifa_addr` is null or a sockaddr sized for its family.
        if let Some(address) = unsafe { socket_ip(entry.ifa_addr) } {
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) };
            // SAFETY: `ifa_netmask` is null or a sockaddr of the same family.
            let prefix_len = match unsafe { socket_ip(entry.ifa_netmask) } {
                Some(IpAddr::V4(mask)) => mask.to_bits().count_ones() as u8,
                Some(IpAddr::V6(mask)) => mask.to_bits().count_ones() as u8,
                None => 0,
            };
            // SAFETY: with IFF_BROADCAST set, `ifa_ifu` is the broadcast
            // address, null or a sockaddr of the same family.
            let broadcast = (entry.ifa_flags & libc::IFF_BROADCAST as u32 != 0)
                .then(|| unsafe { socket_ip(entry.ifa_ifu) })
                .flatten();
            addresses.push(IfAddr {
                interface: name.to_string_lossy().into_owned(),
                address,
                prefix_len,
                broadcast,
            });
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    addresses
}

#[cfg(not(target_os = "linux"))]
fn interface_addresses() -> Vec<IfAddr> {
    Vec::new()
}

/// The IP of an `AF_INET`/`AF_INET6` socket address, None for any other.
///
/// # Safety
/// `addr` is null or points to a socket address as large as its family needs.
#[cfg(target_os = "linux")]
unsafe fn socket_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: non-null, and the caller vouches for the pointee.
    match i32::from(unsafe { (*addr).sa_family }) {
        libc::AF_INET => {
            // SAFETY: an AF_INET address is a sockaddr_in.
            let sin = unsafe { &*addr.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(
                sin.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: an AF_INET6 address is a sockaddr_in6.
            let sin6 = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel prints the table in host byte order; this is a little-endian one.
    #[cfg(target_endian = "little")]
    const ROUTE_V4: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
         eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
         eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
         docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";

    const ROUTE_V6: &str = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n\
         00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n\
         00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
         00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000012 00000000 80200001       lo\n\
         ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 0000000e 00000000 00000001     eth0\n";

    #[test]
    #[cfg(target_endian = "little")]
    fn default_route_v4_takes_the_zero_destination_and_mask() {
        let route = default_route_v4(ROUTE_V4).expect("default route");

        assert_eq!(
            route,
            DefaultRoute {
                interface: "eth0".to_string(),
                gateway: Some("192.168.2.1".parse().unwrap()),
            }
        );
    }

    #[test]
    fn default_route_v6_skips_reject_routes() {
        let route = default_route_v6(ROUTE_V6).expect("default route");

        assert_eq!(
            route,
            DefaultRoute {
                interface: "eth0".to_string(),
                gateway: Some("fe80::1".parse().unwrap()),
            }
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn routes_follow_the_kernel_tables_as_netlink_names_them() {
        let routes = route_entries(
            &parse_routes_v4(ROUTE_V4),
            &parse_routes_v6(ROUTE_V6),
            |interface| interface != "docker0",
        );

        let summary: Vec<String> = routes
            .iter()
            .map(|r| {
                format!(
                    "{} {} {} {} {} {:?}",
                    r.table, r.family, r.scope, r.route_type, r.dst, r.priority
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                "254 inet link unicast 192.168.2.0 Some(100)",
                "254 inet universe unicast default Some(100)",
                "254 inet link unicast 172.17.0.0 None",
                "254 inet6 universe unicast fe80:: Some(256)",
                "254 inet6 universe unicast default Some(1024)",
                "255 inet6 universe local ::1 Some(0)",
                "255 inet6 universe multicast ff00:: Some(256)",
            ],
            "the lo ::/0 reject placeholder is left out"
        );
        assert_eq!(routes[1].gateway.as_deref(), Some("192.168.2.1"));
        assert_eq!(routes[2].flags, ["linkdown"], "docker0 has no carrier");
        assert!(routes[0].flags.is_empty());
        assert_eq!(routes[4].gateway.as_deref(), Some("fe80::1"));
        assert_eq!(routes[4].pref, Some(0));
        assert_eq!(routes[0].pref, None);
    }

    #[test]
    fn address_types_follow_ftl() {
        let kind = |text: &str| address_type(text.parse().unwrap());
        assert_eq!(kind("127.0.0.1"), "loopback");
        assert_eq!(kind("192.168.0.123"), "private");
        assert_eq!(
            kind("100.64.0.1"),
            "private",
            "dnsmasq counts CG-NAT as private"
        );
        assert_eq!(kind("169.254.1.1"), "private");
        assert_eq!(kind("8.8.8.8"), "public");
        assert_eq!(kind("224.0.0.1"), "multicast");
        assert_eq!(kind("::1"), "loopback");
        assert_eq!(kind("fe80::1"), "link-local (LL)");
        assert_eq!(kind("fd00:4711::1"), "site-local (ULA)");
        assert_eq!(kind("2001:db8::1"), "global (GUA)");
        assert_eq!(kind("ff02::1"), "multicast");
        assert_eq!(kind("::ffff:10.0.0.1"), "IPv4-mapped");
    }

    #[test]
    fn interfaces_read_sysfs_and_their_addresses() {
        let root = std::env::temp_dir().join(format!("ferrous-sysnet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        for (file, text) in [
            ("ifindex", "2\n"),
            ("type", "1\n"),
            ("flags", "0x1003\n"),
            ("operstate", "up\n"),
            ("carrier", "1\n"),
            ("speed", "1000\n"),
            ("addr_len", "6\n"),
            ("address", "00:11:22:33:44:55\n"),
            ("broadcast", "ff:ff:ff:ff:ff:ff\n"),
            ("statistics/rx_bytes", "2048\n"),
            ("statistics/tx_bytes", "10\n"),
        ] {
            write(&format!("eth0/{file}"), text);
        }
        for (file, text) in [
            ("ifindex", "1\n"),
            ("type", "772\n"),
            ("flags", "0x9\n"),
            ("operstate", "unknown\n"),
            ("carrier", "1\n"),
            ("addr_len", "6\n"),
            ("address", "00:00:00:00:00:00\n"),
        ] {
            write(&format!("lo/{file}"), text);
        }
        let addresses = [IfAddr {
            interface: "eth0".to_string(),
            address: "192.168.0.123".parse().unwrap(),
            prefix_len: 24,
            broadcast: Some("192.168.0.255".parse().unwrap()),
        }];

        let interfaces = read_interfaces_at(&root, &addresses);
        std::fs::remove_dir_all(&root).expect("cleanup");

        let names: Vec<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["lo", "eth0"], "index order");
        let lo = &interfaces[0];
        assert_eq!(lo.link_type, Some("loopback"));
        assert_eq!(lo.flags, ["up", "loopback", "running", "lower_up"]);
        assert_eq!(lo.speed, None);
        assert!(lo.addresses.is_empty());

        let eth = &interfaces[1];
        assert_eq!(eth.link_type, Some("ether"));
        assert_eq!(
            eth.flags,
            ["up", "broadcast", "running", "multicast", "lower_up"]
        );
        assert_eq!(eth.speed, Some(1000));
        assert_eq!(eth.state, "up");
        assert!(eth.carrier);
        assert_eq!(eth.address.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(
            (eth.stats.rx_bytes.value, eth.stats.rx_bytes.unit.as_str()),
            (2.0, "k")
        );
        let addr = &eth.addresses[0];
        assert_eq!(
            (addr.family, addr.prefixlen, addr.scope),
            ("inet", 24, "universe")
        );
        assert_eq!(addr.address_type, "private");
        assert_eq!(addr.local.as_deref(), Some("192.168.0.123"));
        assert_eq!(addr.broadcast.as_deref(), Some("192.168.0.255"));
        assert_eq!(addr.label.as_deref(), Some("eth0"));
    }

    #[test]
    fn scale_bytes_divides_while_above_1024() {
        let small = scale_bytes(1024);
        assert_eq!((small.value, small.unit.as_str()), (1024.0, ""));

        let large = scale_bytes(3 * 1024 * 1024 * 1024);
        assert_eq!((large.value, large.unit.as_str()), (3.0, "G"));
    }
}
