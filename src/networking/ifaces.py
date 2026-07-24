"""Network interface data class."""


class NetFace:
    """Lightweight wrapper around a network interface dictionary."""
    __slots__ = ('name', 'guid', 'mac', 'ip')

    name: str
    guid: str
    mac: str
    ip: str

    def __init__(self, iface: dict[str, object]) -> None:
        self.name = str(iface['name'])
        self.guid = str(iface['guid'])
        self.mac = str(iface['mac'])
        ips = iface['ips']
        self.ip = str(ips[-1]) if isinstance(ips, list) and ips else '0.0.0.0'

    def __repr__(self) -> str:
        return f'<NAME={self.name}, GUID={self.guid}, MAC={self.mac}, IP={self.ip}>'