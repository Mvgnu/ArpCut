"""Persistent device nickname storage."""
from tools.utils_gui import get_settings, set_settings


class Nicknames:
    """Manages user-defined device nicknames, keyed by MAC address."""

    def __init__(self) -> None:
        self.__db: dict[str, str] = get_settings('nicknames')

    def get_name(self, mac: str) -> str:
        return self.__db.get(mac, '-')

    def set_name(self, mac: str, name: str) -> None:
        self.__db[mac] = name
        set_settings('nicknames', self.__db)

    def reset_name(self, mac: str) -> None:
        if mac in self.__db:
            del self.__db[mac]
        set_settings('nicknames', self.__db)

    @property
    def nicknames_database(self) -> dict[str, str]:
        return self.__db