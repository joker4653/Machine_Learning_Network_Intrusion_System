import time
import math
from statistics import mean, stdev
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
    ip_fields = next((l['fields'] for l in packet_data['layers'] if l['name'] == 'IP'), {})
    l4_fields = next((l['fields'] for l in packet_data['layers'] if l['name'] in ['TCP', 'UDP']), {})

    src_ip = ip_fields.get('src', '')
    dst_ip = ip_fields.get('dst', '')
    proto = ip_fields.get('proto', '')
    
    # Handle cases where ports might be missing (e.g., ICMP or malformed packets)
    try:
        src_port = int(l4_fields.get('sport', 0))
        dst_port = int(l4_fields.get('dport', 0))
    except:
        src_port = 0
        dst_port = 0
    
    if not all([src_ip, dst_ip, proto]):
        return "", False, ("", 0), ("", 0)

    ip_port_a = (src_ip, src_port)
    ip_port_b = (dst_ip, dst_port)

    # Determine canonical order based on IP/Port tuples
    is_forward = ip_port_a < ip_port_b
    
    # Set canonical (A is the lesser IP/Port, B is the greater)
    canonical_a, canonical_b = (ip_port_a, ip_port_b) if is_forward else (ip_port_b, ip_port_a)
    
    # Example key format: 'IP_A:Port_A||IP_B:Port_B||Protocol'
    key_parts = [
        f"{canonical_a[0]}:{canonical_a[1]}",
        f"{canonical_b[0]}:{canonical_b[1]}",
        proto
    ]
    
    return "||".join(key_parts), is_forward, ip_port_a, ip_port_b

class FlowEngine:
    def __init__(self, flow_timeout_sec: int = 60) -> None:
        """
        Docstring for __init__
        
        :param flow_timeout_sec: Time in seconds after an inactive flow is finalised
        :type flow_timeout_sec
        """
        self.active_flows: Dict[str, Dict[str, Any]] = {}
        self.flow_timeout_sec = flow_timeout_sec
        self.finalised_flows = [] # List of Dict[Str,Any]

    def intialise_new_flow(self, key: str, current_time: float) -> None:
        """
        Creates a new flow
        """
        new = FLOW_FEATURE_TEMPLATE.copy()
        new['start_time'] = current_time
        new['last_time'] = current_time
        new['key'] = key
        
        self.active_flows[key] = new
    
    def update_flow_stats(self, flow: Dict[str, Any], packet_data: Dict[str, Any], is_forward: bool, current_time: float) -> None:
        """
        Update all statistics    
        """
        packet_len = packet_data.get('packet_length', 0)
        tcp_flags = packet_data.get('tcp_flags', {})

        # update times
        flow['total_packets'] += 1
        flow['total_bytes'] += packet_len
        flow['timestamps'].append(current_time)
        flow['last_time'] = current_time


        # update directional features
        if is_forward:
            flow['spkts'] += 1
            flow['sbytes'] += packet_len
            flow['s_packet_lengths'].append(packet_len)
        else:
            flow['dpkts'] += 1
            flow['dbytes'] += packet_len
            flow['d_packet_lengths'].append(packet_len)

        # min and max pkt lengths
        if packet_len > flow['max_pkt_len']:
            flow['max_pkt_len'] = packet_len
        if flow['min_pkt_len'] == 0 or packet_len < flow['min_pkt_len']:
            flow['min_pkt_len'] = packet_len
    
        # protocols flags
        if tcp_flags:
            flow['fin_flag_count'] += tcp_flags.get('FIN', 0)
            flow['syn_flag_count'] += tcp_flags.get('SYN', 0)
            flow['rst_flag_count'] += tcp_flags.get('RST', 0)
            flow['psh_flag_count'] += tcp_flags.get('PSH', 0)
            flow['ack_flag_count'] += tcp_flags.get('ACK', 0)
            flow['urg_flag_count'] += tcp_flags.get('URG', 0)

        if packet_data.get('is_fragment', False):
            flow['is_fragmented'] = True

        
        return None
    
    def calculate_stats(self, flow: Dict[str, Any]) -> None:
        """
        Calculate the derived stats required to meet dataset
        
        """

        # rates & durations
        duration = flow['last_time'] - flow['start_time']
        flow['duration'] = duration if duration > 0 else 0.001 # non zero value to avoid division for rates

        if duration > 0:
            flow['rate'] = flow['total_packets'] / duration
            flow['srate'] = flow['spkts'] / duration
            flow['drate'] = flow['dpkts'] / duration

        # packet length statistics
        # pop because we do not need these values after processing the flow.
        # the NN does not expect these values
        source_lengths = flow.pop('s_packet_lengths', [])
        if source_lengths:
            flow['smean'] = mean(source_lengths)
            flow['sdev'] = float(stdev(source_lengths)) if source_lengths.len() > 1 else 0.0

        dest_lengths = flow.pop('d_packet_lengths', [])
        if dest_lengths:
            flow['dmean'] = mean(dest_lengths)
            flow['ddev'] = float(stdev(dest_lengths)) if dest_lengths.len() > 1 else 0.0

        
        # IAT, defined as the amount of time after a packet is received, the next one is received
        timestamps = flow.pop('timestamps', [])
        all_iat = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        flow['mean_iat'] = mean(all_iat)
        flow['stdev_iat'] = float(stdev(all_iat)) if len(all_iat) > 1 else 0.0

    def finalise_flow(self, key: str, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates final entry to flow and moves to finalised flows
        """
        self.calculate_stats(flow)

        del self.active_flows[key]
        self.finalised_flows.append(flow)

        return flow
    
    def process_packet(self, packet_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any] | None]:
        """
        Processes a single deconstructed packet
        
        """
        key, is_foward, ip_port_a, ip_port_b = create_flow_key(packet_data)
        if not key:
            return "", None

        # Create a new flow if does not exist already.
        curr_time = time.time()

        if key not in self.active_flows:
            self.intialise_new_flow(key, curr_time)

        self.update_flow_stats(self.active_flows[key], packet_data, is_foward, curr_time)

        finalised = self.check_for_timeouts(curr_time)
        # currently return the flow + key, in the future we expect to just store this on a queue
        return key, finalised
    
    def check_for_timeouts(self, current_time: float):
        """
        Checks for Keys which need to be finalised based on self.flow_timeout
        Keys that are finalised, will be added to the finalised flows list
        """
        to_be_finalised = []
        for key, flow in self.active_flows.items():
            if current_time - flow['last_time'] > self.flow_timeout_sec:
                to_be_finalised.append(key)

        for key in to_be_finalised:
            flow = self.active_flows[key]
            self.finalise_flow(key, flow)