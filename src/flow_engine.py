import time
import math
import statistics
from typing import Dict, Any, Tuple, List

# NF-UNSW-NB15 Feature Template
FLOW_FEATURE_TEMPLATE = {
    # Temporal & Basic Aggregates
    'duration': 0.0,            # Duration of the flow
    'total_packets': 0,         # Total packets in the flow
    'total_bytes': 0,           # Total bytes in the flow
    'start_time': 0.0,          # Unix timestamp of the first packet
    'last_time': 0.0,           # Unix timestamp of the last packet
    
    # Directional Aggregates
    'spkts': 0,                 # Source to destination packet count
    'dpkts': 0,                 # Destination to source packet count
    'sbytes': 0,                # Source to destination bytes
    'dbytes': 0,                # Destination to source bytes
    
    # Lists for Statistical Calculation & Timing
    's_packet_lengths': [],     # List of packet lengths from source
    'd_packet_lengths': [],     # List of packet lengths from destination
    'timestamps': [],           # List of packet timestamps (for IAT calculation)

    # TCP Flag Counters
    'fin_flag_count': 0,
    'syn_flag_count': 0,
    'rst_flag_count': 0,
    'psh_flag_count': 0,
    'ack_flag_count': 0,
    'urg_flag_count': 0,

    # Calculated Statistical Features (Derived in finalize_flow)
    'rate': 0.0,                # Packet rate (pkts/sec)
    'srate': 0.0,               # Source packet rate (spkts/sec)
    'drate': 0.0,               # Destination packet rate (dpkts/sec)
    
    # Packet Length Statistics
    'smean': 0.0,               # Mean packet size (source)
    'dmean': 0.0,               # Mean packet size (destination)
    'sdev': 0.0,                # Standard deviation of packet size (source)
    'ddev': 0.0,                # Standard deviation of packet size (destination)
    'min_pkt_len': 0.0,         # Minimum packet length
    'max_pkt_len': 0.0,         # Maximum packet length
    
    # Inter-Arrival Time (IAT) Statistics
    'stdev_iat': 0.0,           # Standard deviation of Inter-Arrival Time
    'mean_iat': 0.0,            # Mean Inter-Arrival Time

    'is_fragmented': False,     # Flag if any packet in the flow was fragmented
    
    # Simplified Contextual Flow Count Features 
    'ct_srv_src': 1,            # Placeholder: Count of flows to the same service and source IP.
    'ct_state_ttl': 60,         # Placeholder: Time-to-live or connection state value.
}


def create_flow_key(packet_data: Dict[str, Any]) -> Tuple[str, bool, Tuple[str, int], Tuple[str, int]]:
    """
    create a directional flow key as standard
    
    returns: (canonical_key, is_forward_direction, ip_port_a, ip_port_b)
              is_forward_direction is True if the packet matches the canonical 'A->B' direction.
    
    """


class FlowEngine:
    def __init__(self, flow_timeout_sec: int = 60) -> None:
        """
        Docstring for __init__
        
        :param flow_timeout_sec: Time in seconds after an inactive flow is finalised
        :type flow_timeout_sec
        """


    def intialise_new_flow(self, key: str, current_time: float) -> None:
        """
        Creates a new flow
        """
        return None
    
    def update_flow_stats(self, flow: Dict[str, Any], packet_data: Dict[str, Any], is_forward: bool, current_time: float) -> None:
        """
        Update all statistics    
        """    
        return None
    
    def calculate_stats(self, flow: Dict[str, Any]) -> None:
        """
        Calculate the derived stats required to meet dataset
        
        """
        return None

    def finalise_flow(self, key: str, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates final entry to flow and moves to finalised flows
        """
        return {}

    def process_packet(self, packet_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any] | None]:
        """
        Processes a single deconstructed packet
        
        """
        return None