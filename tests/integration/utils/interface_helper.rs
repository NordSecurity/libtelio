use std::net::IpAddr;

use super::process::run_command;

pub struct InterfaceHelper {
    next_tun_num: u32,
}

impl InterfaceHelper {
    pub fn new() -> Self {
        Self { next_tun_num: 10 }
    }

    pub fn new_ifc_name(&mut self) -> String {
        let tun_name = format!("tun{}", self.next_tun_num);
        self.next_tun_num += 1;
        tun_name
    }

    pub fn configure_ifc(ifc_name: &str, ip: IpAddr) {
        run_command(
            &[
                "ip",
                "-4",
                "addr",
                "add",
                ip.to_string().as_str(),
                "dev",
                ifc_name,
            ],
            &[""],
        )
        .unwrap();
        run_command(&["ip", "link", "set", "up", "dev", ifc_name], &[""]).unwrap();
    }

    pub fn create_vpn_route(ifc_name: &str) {
        for network in ["10.0.0.0/16", "100.64.0.1", "10.5.0.0/16"] {
            run_command(
                &[
                    "ip", "route", "add", network, "dev", ifc_name, "table", "73110",
                ],
                &[""],
            )
            .unwrap();
        }
        let _ = run_command(
            &[
                "ip", "rule", "add", "priority", "32111", "not", "from", "all", "fwmark",
                "11673110", "lookup", "73110",
            ],
            &["RTNETLINK answers: File exists"],
        )
        .unwrap();
    }
}

impl Drop for InterfaceHelper {
    fn drop(&mut self) {
        for i in 10..self.next_tun_num {
            let ifc_name = format!("tun{i}");
            run_command(
                &["ip", "link", "delete", ifc_name.as_str()],
                &["Cannot find device"],
            )
            .unwrap();
        }
        run_command(&["ip", "rule", "del", "priority", "32111"], &[""]).unwrap();
    }
}
