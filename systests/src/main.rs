use tests::{meshnet::test_meshnet_poc, vpn::test_vpn_poc};

mod tests;
mod utils;

fn main() {
    test_meshnet_poc();
    test_vpn_poc();
}
