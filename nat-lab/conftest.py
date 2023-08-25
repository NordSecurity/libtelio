import os


def pytest_runtest_setup(item):
    if any(mark for mark in item.iter_markers() if mark.name == "derp"):
        for derp in ["nat-lab-derp-01-1", "nat-lab-derp-02-1", "nat-lab-derp-03-1"]:
            os.system(f"docker exec -d {derp} bash -c 'pkill nordderper ; nordderper'")
