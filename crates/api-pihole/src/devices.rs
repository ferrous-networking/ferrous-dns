//! Devices as FTL's network table keeps them, gathered from client rows:
//! the clients that share a MAC address, or FTL's `ip-<address>` mock
//! hardware address for a client without one.

use std::collections::HashMap;

use ferrous_dns_domain::Client;

use crate::crud::unix_seconds;

pub(crate) struct Device<'a> {
    /// Lowercase, as FTL stores it.
    pub hwaddr: String,
    /// In the order the rows came.
    pub clients: Vec<&'a Client>,
}

impl Device<'_> {
    /// When any of the device's addresses last queried.
    pub fn last_query(&self) -> i64 {
        self.clients
            .iter()
            .map(|client| unix_seconds(client.last_seen.as_deref()))
            .max()
            .unwrap_or(0)
    }
}

/// Groups `clients` into devices, most recently active first.
pub(crate) fn group_devices(clients: &[Client]) -> Vec<Device<'_>> {
    let mut devices: Vec<Device<'_>> = Vec::new();
    let mut by_hwaddr: HashMap<String, usize> = HashMap::new();
    for client in clients {
        let hwaddr = client.mac_address.as_deref().map_or_else(
            || format!("ip-{}", client.ip_address),
            str::to_ascii_lowercase,
        );
        let slot = *by_hwaddr.entry(hwaddr.clone()).or_insert_with(|| {
            devices.push(Device {
                hwaddr,
                clients: Vec::new(),
            });
            devices.len() - 1
        });
        devices[slot].clients.push(client);
    }

    devices.sort_by_key(|device| std::cmp::Reverse(device.last_query()));
    devices
}
