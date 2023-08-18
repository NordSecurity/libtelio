import os


def pytest_runtest_setup():
    os.system("docker exec nat-lab-vpn-01-1 bash -c 'wg setconf wg0 /wg0.conf'")
    os.system("docker exec nat-lab-vpn-02-1 bash -c 'wg setconf wg0 /wg0.conf'")
    os.system(
        "docker exec -d nat-lab-derp-01-1 bash -c 'pkill nordderper ; nordderper'"
    )
    os.system(
        "docker exec -d nat-lab-derp-02-1 bash -c 'pkill nordderper ; nordderper'"
    )
    os.system(
        "docker exec -d nat-lab-derp-03-1 bash -c 'pkill nordderper ; nordderper'"
    )
