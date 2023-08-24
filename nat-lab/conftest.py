import natlab


def pytest_runtest_setup(item):
    if any(mark for mark in item.iter_markers() if mark.name == "derp"):
        natlab.quick_restart_container(["derp"])
