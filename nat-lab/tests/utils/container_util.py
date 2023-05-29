from aiodocker import Docker
from utils.connection import Connection, DockerConnection
from utils.process import ProcessExecError
from utils import LinuxRouter


async def reset(connection: Connection) -> None:
    try:
        # JIRA issue: LLT-459
        await connection.create_process(
            ["killall", "tcli", "derpcli", "ping", "nc", "iperf3"]
        ).execute()
    except ProcessExecError as exception:
        if exception.stderr.find("no process found") < 0:
            raise exception

    router = LinuxRouter(connection)

    await router.delete_interface()

    await router.delete_vpn_route()
    await router.delete_exit_node_route()


async def get(docker: Docker, container_name: str) -> DockerConnection:
    container = await docker.containers.get(container_name)
    connection = DockerConnection(container)
    await reset(connection)
    return connection
