import os


def pytest_runtest_setup(item):
    if any(mark for mark in item.iter_markers() if mark.name == "vpn"):
        os.system("docker exec nat-lab-vpn-01-1 bash -c 'wg setconf wg0 /wg0.conf'")
        os.system("docker exec nat-lab-vpn-02-1 bash -c 'wg setconf wg0 /wg0.conf'")

    if any(mark for mark in item.iter_markers() if mark.name == "derp"):
        os.system(
            "docker exec -d nat-lab-derp-01-1 bash -c 'pkill nordderper ; nordderper'"
        )
        os.system(
            "docker exec -d nat-lab-derp-02-1 bash -c 'pkill nordderper ; nordderper'"
        )
        os.system(
            "docker exec -d nat-lab-derp-03-1 bash -c 'pkill nordderper ; nordderper'"
        )
