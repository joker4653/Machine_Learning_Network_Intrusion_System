import scapy
from multiprocessing import Queue, Process

class NetworkMonitor():
    def __init__(self, input_queue, network_adapter = None) -> None:
        self.network_adapter = 'eth0' if network_adapter is None else network_adapter
        self.queue = input_queue
        self.process = None
        self.running = None

    def start(self) -> Process | None:
        """
        Calls cycle to monitor the network adapter located at var network_adapter (default eth0).

        Returns: The handle to the monitoring process, else None
        """
        
    def stop(self) -> bool:
        """
        Forces the process to stop monitoring for packets by setting a is running value
        
        Returns: True if successful, False if failed.
        """
        return False

    def cycle(self) -> None:
        """
        Continuously loops and sniffs packets. For each packet, runs "deconstruct_packet" and stores it on the queue for processing by
        the detection engine.

        Returns: None
        """
        return
    
    def deconstruct_packet(self, packet) -> dict[str, str]:
        """
        Will deconstruct a packet into a dictionary of the following form:
        {
        src_ip: xx,
        dest_ip: xx,
        etc
        }

        args: 
            packet (byte): Packet sniffed and provided as raw bytes.

        Returns: A packet deconstructed into its headers in a dictionary object.
        """
        return {}