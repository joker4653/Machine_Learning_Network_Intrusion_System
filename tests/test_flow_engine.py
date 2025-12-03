import pytest
import time
from unittest.mock import patch

# --- Mock Packet Data Fixtures ---

# These fixtures mimic the output structure of deconstruct_packet()
# Note: packet_length is crucial for byte counting.

@pytest.fixture
def p1_a_to_b():
    """Packet 1: A (192.168.1.100:54321) -> B (8.8.8.8:80) TCP, 1500 bytes"""
    return {
        "layers": [
            {"name": "IP", "fields": {"src": "192.168.1.100", "dst": "8.8.8.8", "proto": "6"}},
            {"name": "TCP", "fields": {"sport": "54321", "dport": "80"}},
            {"name": "Raw"}
        ],
        "packet_length": 1500, 
        "summary": "P1"
    }

@pytest.fixture
def p2_b_to_a():
    """Packet 2: B (8.8.8.8:80) -> A (192.168.1.100:54321) TCP, 500 bytes (Reverse direction)"""
    return {
        "layers": [
            {"name": "IP", "fields": {"src": "8.8.8.8", "dst": "192.168.1.100", "proto": "6"}},
            {"name": "TCP", "fields": {"sport": "80", "dport": "54321"}},
            {"name": "Raw"}
        ],
        "packet_length": 500,
        "summary": "P2"
    }

@pytest.fixture
def p3_new_flow():
    """Packet 3: C (10.0.0.1:10000) -> D (10.0.0.2:443) UDP, 100 bytes (New flow)"""
    return {
        "layers": [
            {"name": "IP", "fields": {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "17"}},
            {"name": "UDP", "fields": {"sport": "10000", "dport": "443"}},
            {"name": "Raw"}
        ],
        "packet_length": 100,
        "summary": "P3"
    }

# --- TESTS FOR create_flow_key ---

def test_flow_key_canonicalization(p1_a_to_b, p2_b_to_a):
    """
    Ensures that packets in both directions of the same session 
    generate the exact same canonical flow key.
    """
    key_forward = create_flow_key(p1_a_to_b)
    key_reverse = create_flow_key(p2_b_to_a)
    
    # Example key format should be like: '8.8.8.8:80||192.168.1.100:54321||6' (Sorted IP/Port)
    assert key_forward == key_reverse
    assert key_forward == '8.8.8.8:80||192.168.1.100:54321||6'

def test_flow_key_protocol_separation(p1_a_to_b, p3_new_flow):
    """Ensures keys for different protocols are unique."""
    key_tcp = create_flow_key(p1_a_to_b) # Protocol 6
    key_udp = create_flow_key(p3_new_flow) # Protocol 17
    
    assert key_tcp != key_udp

# --- TESTS FOR FlowEngine CLASS ---

@patch('time.time')
def test_flow_initialization_and_packet_aggregation(mock_time, p1_a_to_b, p2_b_to_a):
    """Tests that a new flow is initialized and subsequent packets are aggregated."""
    engine = FlowEngine(flow_timeout_sec=10)
    
    # --- Step 1: Process P1 (Start) ---
    mock_time.return_value = 1000.0  # Freeze time at 1000.0
    key, final_data = engine.process_packet(p1_a_to_b)
    
    assert key in engine.active_flows
    flow = engine.active_flows[key]
    assert flow['total_packets'] == 1
    assert flow['total_bytes'] == 1500
    assert flow['start_time'] == 1000.0
    assert flow['last_time'] == 1000.0
    
    # --- Step 2: Process P2 (Update) ---
    mock_time.return_value = 1001.5  # Advance time by 1.5 seconds
    key, final_data = engine.process_packet(p2_b_to_a)
    
    assert key in engine.active_flows
    flow = engine.active_flows[key]
    assert flow['total_packets'] == 2 # 1 + 1
    assert flow['total_bytes'] == 2000 # 1500 + 500
    assert flow['start_time'] == 1000.0 # Start time unchanged
    assert flow['last_time'] == 1001.5 # Last time updated

@patch('time.time')
def test_flow_timeout_and_feature_finalization(mock_time, p1_a_to_b):
    """Tests that flows are finalized correctly when they timeout."""
    engine = FlowEngine(flow_timeout_sec=5)
    
    # 1. Process P1 (Start)
    mock_time.return_value = 2000.0
    key, _ = engine.process_packet(p1_a_to_b)
    assert len(engine.active_flows) == 1
    
    # 2. Advance time *past* timeout
    mock_time.return_value = 2007.0 # 7 seconds later (timeout is 5s)
    
    # 3. Check for timeouts (triggered by the next packet or explicit check)
    final_data = engine.check_and_flush_timeouts(mock_time.return_value)
    
    assert len(engine.active_flows) == 0 # Flow should be removed
    assert final_data is not None
    assert final_data['total_packets'] == 1
    
    # Duration should be the difference between mock_time and start_time (2007 - 2000)
    assert final_data['duration'] == pytest.approx(7.0)
    
    # Rate should be total_packets / duration (1 / 7)
    assert final_data['packet_rate_per_sec'] == pytest.approx(1 / 7)
    assert final_data in engine.finalized_flows

@patch('time.time')
def test_multiple_flows_coexistence(mock_time, p1_a_to_b, p3_new_flow):
    """Tests that multiple independent flows can be tracked simultaneously."""
    engine = FlowEngine(flow_timeout_sec=10)
    
    mock_time.return_value = 3000.0
    key_A, _ = engine.process_packet(p1_a_to_b)
    
    mock_time.return_value = 3000.1 # Small delay
    key_B, _ = engine.process_packet(p3_new_flow)
    
    assert len(engine.active_flows) == 2
    assert key_A != key_B
    assert engine.active_flows[key_A]['total_packets'] == 1
    assert engine.active_flows[key_B]['total_packets'] == 1