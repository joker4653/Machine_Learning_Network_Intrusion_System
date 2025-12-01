import pytest
from multiprocessing import Queue, Process
from src.network.monitor_network import NetworkMonitor
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP, fragment
from scapy.all import Packet, Raw
SAMPLE_QUEUE_SIZE = 10


@pytest.fixture
def mock_monitor():
    return NetworkMonitor(Queue(SAMPLE_QUEUE_SIZE))

@pytest.fixture
def started_monitor(mock_monitor):
    mock_monitor.start()
    return started_monitor

@pytest.fixture
def mock_packet():
    return  Ether(dst="00:11:22:33:44:55", src="AA:BB:CC:DD:EE:FF") / \
            IP(src="192.168.1.100", dst="8.8.8.8") / \
            TCP(sport=54321, dport=80) / \
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

@pytest.fixture
def fragmented_packet():
    """Returns the first fragment of a large packet to test the is_fragment flag."""
    # Create a large packet
    p = IP(src="10.0.0.1", dst="10.0.0.2") / TCP() / Raw(load=b'A' * 2000)
    # Fragment it into smaller pieces
    fragments = fragment(p, fragsize=500)
    # Return the first fragment, which will have the 'More Fragments' flag set.
    return fragments[0]


class TestNetworkMonitor:
    """Tests for the monitor_network.py file in src/network/monitor_network.py"""

    def test_intialise_NetworkMonitor_class(self):
        monitor = NetworkMonitor(Queue(SAMPLE_QUEUE_SIZE))
        assert isinstance(monitor, NetworkMonitor)
        assert monitor.network_adapter == 'eth0', "network adapter intialised to non default."
        assert isinstance(monitor.queue, Queue), "queue was not intialised to a Queue object."

        monitor2 = NetworkMonitor(Queue(SAMPLE_QUEUE_SIZE), "fake_adapter")
        assert monitor2.network_adapter == "fake_adapter", "adapter did not intialise to argument provided."


    def test_start_returns_process(self, mock_monitor):
        assert isinstance(mock_monitor.start(), Process), "start did not return a process"

    def test_stop_return_true(self, started_monitor):
        assert started_monitor.stop() == True, "stop function failed to stop a running process"

    def test_stop_return_false(self, mock_monitor):
        assert mock_monitor.stop() == False, "stop function failed to handle a non running monitor"

    def test_cycle_adds_to_queue(self):
        pass

    def test_cycle_handles_bad_packet(self):
        pass

    def test_deconstruct_packet_correctly(self, mock_packet : Packet, mock_monitor: NetworkMonitor):
        analysis = mock_monitor.deconstruct_packet(mock_packet)
        
        assert isinstance(analysis, dict)
        assert "summary" in analysis
        assert "layers" in analysis
        assert "raw_payload_data" in analysis
        assert "IP" in analysis["summary"]
        assert "TCP" in analysis["summary"]
        assert "Raw" in analysis["summary"]

    def test_deconstruct_layer_count_and_order(self, mock_packet: Packet, mock_monitor: NetworkMonitor):
        analysis = mock_monitor.deconstruct_packet(mock_packet)
        
        assert len(analysis["layers"]) == 4
        # Check layer names in order
        assert analysis["layers"][0]["name"] == "Ethernet"
        assert analysis["layers"][1]["name"] == "IP"
        assert analysis["layers"][2]["name"] == "TCP"
        assert analysis["layers"][3]["name"] == "Raw"

    def test_deconstruct_ip_header_fields(self, mock_packet: Packet, mock_monitor: NetworkMonitor):
        analysis = mock_monitor.deconstruct_packet(mock_packet)
        # IP is the second layer (index 1)
        ip_layer_fields = analysis["layers"][1]["fields"]
        
        assert ip_layer_fields.get("src") == "192.168.1.100"
        assert ip_layer_fields.get("dst") == "8.8.8.8"

    def test_deconstruct_tcp_header_fields(self, mock_packet: Packet, mock_monitor: NetworkMonitor):
        analysis = mock_monitor.deconstruct_packet(mock_packet)
        # TCP is the third layer (index 2)
        tcp_layer_fields = analysis["layers"][2]["fields"]
        
        # Note: Scapy's fields are converted to strings in the helper function
        assert tcp_layer_fields.get("sport") == "54321"
        assert tcp_layer_fields.get("dport") == "80"

    def test_deconstruct_raw_payload_data_extraction(self, mock_packet: Packet, mock_monitor: NetworkMonitor):
        analysis = mock_monitor.deconstruct_packet(mock_packet)
        expected_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        assert analysis["raw_payload_data"] == expected_payload
        
    def test_deconstruct_fragmentation_flag(self, fragmented_packet, mock_packet, mock_monitor: NetworkMonitor):
        # Test for fragmented packet
        analysis_frag = mock_monitor.deconstruct_packet(fragmented_packet)
        assert analysis_frag["is_fragment"] is True
        
        # Test for non-fragmented packet
        analysis_non_frag = mock_monitor.deconstruct_packet(mock_packet)
        assert analysis_non_frag["is_fragment"] is False

    def test_deconstruct_malformed_packet(self, mock_monitor : NetworkMonitor):
        with pytest.raises(ValueError):
            mock_monitor.deconstruct_packet("fake object")
        
