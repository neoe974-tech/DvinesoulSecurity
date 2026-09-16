from dvinesoul_security.core.system import print_system_info
from dvinesoul_security.core.processes import print_processes
from dvinesoul_security.core.services import print_services
from dvinesoul_security.network.interfaces import print_interfaces
from dvinesoul_security.network.connections import print_connections


def main() -> None:
    print_system_info()
    print_processes()
    print_services()
    print_interfaces()
    print_connections()


if __name__ == "__main__":
    main()
