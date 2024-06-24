//! Telio constants definition

/// VPN IPv4 Meshnet Address
pub const VPN_INTERNAL_IPV4: [u8; 4] = [100, 64, 0, 1];
/// VPN IPv6 Meshnet Address
pub const VPN_INTERNAL_IPV6: [u16; 8] = [0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 1];
/// VPN IPv4 Non-Meshnet Address
pub const VPN_EXTERNAL_IPV4: [u8; 4] = [10, 5, 0, 1];
