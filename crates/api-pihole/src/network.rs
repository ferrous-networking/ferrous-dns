//! The default-route interfaces `/padd` reports under `iface`, read from the
//! kernel's routing tables (`/proc/net/route`, `/proc/net/ipv6_route`), the
//! interface addresses and the `/sys/class/net` counters. FTL asks netlink
//! for the same data. All of it blocks, so call it from `spawn_blocking`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dto::padd::{PaddByteCount, PaddIface, PaddIfaceV4, PaddIfaceV6};

/// `RTF_UP` and `RTF_REJECT` of `<linux/route.h>`.
const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// A default route: the interface it leaves through and its next hop.
#[derive(Debug, PartialEq)]
struct DefaultRoute {
    interface: String,
    gateway: Option<IpAddr>,
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
    addresses: &'a [(String, IpAddr)],
    interface: Option<&str>,
    family: fn(&IpAddr) -> bool,
) -> Vec<&'a IpAddr> {
    let Some(interface) = interface else {
        return Vec::new();
    };
    addresses
        .iter()
        .filter(|(name, addr)| name == interface && family(addr))
        .map(|(_, addr)| addr)
        .collect()
}

/// First up route of `/proc/net/route` with a zero destination and mask.
/// Addresses are the network-order bytes printed as a host-order number.
fn default_route_v4(table: &str) -> Option<DefaultRoute> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [interface, destination, gateway, flags, _, _, _, mask, ..] = fields[..] else {
            return None;
        };
        let hex = |field: &str| u32::from_str_radix(field, 16).ok();
        let is_default = hex(destination)? == 0 && hex(mask)? == 0;
        if !is_default || hex(flags)? & RTF_UP == 0 {
            return None;
        }
        let gateway = hex(gateway)?;
        Some(DefaultRoute {
            interface: interface.to_string(),
            gateway: (gateway != 0).then(|| IpAddr::V4(Ipv4Addr::from(gateway.to_ne_bytes()))),
        })
    })
}

/// First up, non-reject `::/0` route of `/proc/net/ipv6_route`, whose
/// fields are: destination, prefix length, source, source prefix length,
/// next hop, metric, refcount, use, flags, interface.
fn default_route_v6(table: &str) -> Option<DefaultRoute> {
    table.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [destination, prefix_len, _, _, next_hop, _, _, _, flags, interface] = fields[..]
        else {
            return None;
        };
        let is_default = u128::from_str_radix(destination, 16).ok()? == 0
            && u8::from_str_radix(prefix_len, 16).ok()? == 0;
        let flags = u32::from_str_radix(flags, 16).ok()?;
        if !is_default || flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
            return None;
        }
        let next_hop = u128::from_str_radix(next_hop, 16).ok()?;
        Some(DefaultRoute {
            interface: interface.to_string(),
            gateway: (next_hop != 0).then(|| IpAddr::V6(Ipv6Addr::from(next_hop))),
        })
    })
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

/// Every interface address as `(interface, address)`, in the kernel's order.
#[cfg(target_os = "linux")]
fn interface_addresses() -> Vec<(String, IpAddr)> {
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
        if let Some(addr) = unsafe { socket_ip(entry.ifa_addr) } {
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) };
            addresses.push((name.to_string_lossy().into_owned(), addr));
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    addresses
}

#[cfg(not(target_os = "linux"))]
fn interface_addresses() -> Vec<(String, IpAddr)> {
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
    #[test]
    #[cfg(target_endian = "little")]
    fn default_route_v4_takes_the_zero_destination_and_mask() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                     eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";

        let route = default_route_v4(table).expect("default route");

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
        let table = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n\
                     00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n";

        let route = default_route_v6(table).expect("default route");

        assert_eq!(
            route,
            DefaultRoute {
                interface: "eth0".to_string(),
                gateway: Some("fe80::1".parse().unwrap()),
            }
        );
    }

    #[test]
    fn scale_bytes_divides_while_above_1024() {
        let small = scale_bytes(1024);
        assert_eq!((small.value, small.unit.as_str()), (1024.0, ""));

        let large = scale_bytes(3 * 1024 * 1024 * 1024);
        assert_eq!((large.value, large.unit.as_str()), (3.0, "G"));
    }
}
