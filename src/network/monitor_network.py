import scapy
from scapy.all import sniff, Raw, Packet
from multiprocessing import Queue, Process
import time

class NetworkMonitor():
    def __init__(self, input_queue : Queue, network_adapter = None) -> None:
        self.network_adapter = 'eth0' if network_adapter is None else network_adapter
        self.queue = input_queue
        self.process = None
        self.running = False

    def start(self) -> Process | None:
        """
        Calls cycle to monitor the network adapter located at var network_adapter (default eth0).

        Returns: The handle to the monitoring process, else None
        """
        if self.running == True:
            pass
        self.running = True
        self.process = Process(target=self.cycle,)
        if self.process is None:
            raise ValueError("Process not correctly created")
        return self.process
        
    def stop(self) -> bool:
        """
        Forces the process to stop monitoring for packets by setting a is running value
        
        Returns: True if successful, False if failed.
        """
        if self.running == False:
            return False
        
        # by setting self.running to false we naturally let our cycle to end without termination
        self.running = False
        
        return True

    def cycle(self) -> None:
        """
        Continuously loops and sniffs packets. For each packet, runs "deconstruct_packet" and stores it on the queue for processing by
        the detection engine.

        Returns: None
        """
        def packet_callback(pkt: Packet) -> None:
            processed = self.deconstruct_packet(pkt)
            try:
                self.queue.put_nowait(processed)
            except Exception as e:
                print(f"DROPPED PACKET DUE TO QUEUE BEING FULL: {e}")

        while self.running:
            try:
                sniff(iface=self.network_adapter, prn=packet_callback, store=0, timeout=5)
            except OSError as e:
                print(f"Error during sniffing on {self.network_adapter}: {e}")
                break
            except Exception as e:
                print(f"Unexpected error occured in cycle loop: {e}")
                break

        print(f"Monitoring cycle on {self.network_adapter} has stopped.")
        return
    
    def __helper_deconstruct_packet(self, layer) -> dict:
        """Helper function which extracts field names and values from a scapy layer"""
        data = {}

        for field, value in layer.fields.items():
            if field == 'options' and isinstance(value, list):
                data[field] = [opt.name for opt in value]
            else:
                data[field] = str(value)

        return data

    def deconstruct_packet(self, packet) -> dict:
        """
        Will deconstruct a packet into a dictionary of the following form:
        {
        src_ip: xx,
        dest_ip: xx,
        etc
        }

        args: 
            packet (Packet): Packet sniffed and provided as scapy packet object.

        Returns: A packet deconstructed into its headers in a dictionary object.
        """
        if not isinstance(packet, Packet):
            raise ValueError("Not a Packet value")
        
        analysis_result = {
            "summary": packet.summary(),
            "packet_length": len(packet),
            "packet_timestamp": getattr(packet, 'time', time.time()), 
            "layers": [],
            "raw_payload_data": None,
            "is_fragment": False,
            "tcp_flags": {}
        }

        current_layer = packet
        
        # Iterate through the layers until the payload is exhausted
        while current_layer:
            layer_name = current_layer.name
            
            layer_data = {
                "name": layer_name,
                "fields": self.__helper_deconstruct_packet(current_layer),
                "summary": current_layer.summary()
            }
            
            # Check for the Raw layer to extract the application data payload
            if layer_name == 'Raw':
                # Store the raw load bytes directly for pattern matching
                analysis_result["raw_payload_data"] = bytes(current_layer.load)
            
            analysis_result["layers"].append(layer_data)
            
            # Check for IP fragmentation flags (only for IP layer)
            if layer_name == 'IP':
                if current_layer.flags & 0x01 or current_layer.frag != 0: # Check MF or FO
                    analysis_result["is_fragment"] = True

            if layer_name == 'TCP':
            # Added flags to be piped into flow similar to model dataset
                flags_value = current_layer.flags
                analysis_result["tcp_flags"] = {
                    "FIN": 1 if flags_value.F else 0, # F: FIN (Used for connection teardown)
                    "SYN": 1 if flags_value.S else 0, # S: SYN (Used for connection initiation, high for scanning)
                    "RST": 1 if flags_value.R else 0, # R: RST (Used for abrupt termination, high for abnormal flows)
                    "PSH": 1 if flags_value.P else 0, # P: PSH (Used for pushing data immediately)
                    "ACK": 1 if flags_value.A else 0, # A: ACK (Used for acknowledging data)
                    "URG": 1 if flags_value.U else 0, # U: URG (Urgent pointer field significant)
                }

            # Move to the next layer
            if current_layer.payload:
                current_layer = current_layer.payload
            else:
                break
                
        return analysis_result