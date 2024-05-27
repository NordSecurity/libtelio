# mypy: ignore-errors
# autoflake: skip_file
# pylint: skip-file

from sys import exit
from SystemConfiguration import SCDynamicStoreCreate, SCDynamicStoreCopyValue


def main():
    interfaces_with_router_prop = 0
    store = SCDynamicStoreCreate(None, "demo.controller", None, None)
    service_ids = SCDynamicStoreCopyValue(store, "Setup:/Network/Global/IPv4")

    for id in service_ids["ServiceOrder"]:
        dict = SCDynamicStoreCopyValue(store, f"State:/Network/Service/{id}/IPv4")
        if dict:
            if "Router" in dict:
                interfaces_with_router_prop += 1
                if "SubnetMasks" in dict:
                    print(
                        id,
                        "name:",
                        dict["InterfaceName"],
                        "addr:",
                        dict["Addresses"][0],
                        "mask:",
                        dict["SubnetMasks"][0],
                        "router:",
                        dict["Router"],
                    )
                else:
                    print(
                        id,
                        "name:",
                        dict["InterfaceName"],
                        "addr:",
                        dict["Addresses"][0],
                        "router:",
                        dict["Router"],
                    )
            else:
                pass


if __name__ == "__main__":
    main()
