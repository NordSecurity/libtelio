#![cfg(windows)]

use super::tunnel::winipcfg::luid::InterfaceLuid;

pub fn cleanup_network_config(luid: u64) {
    // Clean up like in InterfaceWatcher::Destroy() in /3rd-party/wireguard-go/interfacewatcher_windows.go
    // It was called from wg_go_stop() in our wireguard-go wrapper, which is strange,
    // but probably in order not to modify wireguard-go source. The InterfaceWatcher
    // was used to detect when our adapter was assigned an IP address,
    // but it also offered this very useful bit of clean-up code.
    //
    // Original comment from wireguard-go:
    // "It seems that the Windows networking stack doesn't like it when we destroy interfaces
    // that have active routes, so to be certain, just remove everything before destroying."

    let iface = InterfaceLuid::new(luid);

    #[allow(unused)]
    {
        // Ignore Result<> of the functions below, it only has diagnostic purposes
        iface.flush_routes_ipv4();
        iface.flush_ipv4_addresses();
        iface.flush_dns_ipv4();

        iface.flush_routes_ipv6();
        iface.flush_ipv6_addresses();
        iface.flush_dns_ipv6();
    }
}
