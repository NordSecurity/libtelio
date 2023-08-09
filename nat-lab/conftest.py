import pytest


def pytest_collection_modifyitems(items):
    # Separate test execution into layers based on platform. The biggest reason
    # for this is to separate `linux_native` tests. If the tests are running
    # normally, they are interleaved, e.g.:
    # Test1-BoringTun, Test1-LinuxNative, Test2-BoringTun, Test2-LinuxNative.
    # For whatever reason, `linux_native` tests that connect to VPN server take
    # 30 seconds to run, if they are executed after the same BoringTun test.
    # Given 4 tests like that, interleaving increases test execution time by 2 minutes.

    for item in items:
        order_index = 1
        for mark in item.iter_markers():
            if mark.name == "linux_native":
                order_index = 0
            elif mark.name == "windows":
                order_index = 2
            elif mark.name == "mac":
                order_index = 3
            elif mark.name == "long":
                order_index = 4

        item.add_marker(pytest.mark.order(order_index))
