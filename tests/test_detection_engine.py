import pytest
from unittest.mock import MagicMock
from src.detection_engine import DetectionEngine
from multiprocessing import Queue
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP, fragment
from scapy.all import Packet, Raw

@pytest.fixture
def mock_config():
    #TBD
    return {}

@pytest.fixture
def mock_detection_engine(mock_config):
    return DetectionEngine(config=mock_config, input_queue=Queue(5))

@pytest.fixture
def mock_packet():
    return  Ether(dst="00:11:22:33:44:55", src="AA:BB:CC:DD:EE:FF") / \
            IP(src="192.168.1.100", dst="8.8.8.8") / \
            TCP(sport=54321, dport=80) / \
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")


class TestDetectionEngine:

    def test_initialise_instance(self, mock_config):
        """
        Verifies that detection engine intiialise with a correct config.
        """
        engine = DetectionEngine(config=mock_config, input_queue=Queue(5))

        assert isinstance(engine, DetectionEngine), "DectectionEngine instance was not initialised properly."

        assert engine.config == mock_config, "Config not set correctly."
    
        # insert assert all public variables are set correctly.
        # i.e. self.network_thread is not None.
        return False
    
    def test_setup_network_thread(self, mock_detection_engine):
        #assert isinstance(mock_detection_engine.network_monitor, NetworkMonitor), "Network Monitoring Process not setup correctly."
        pass

    def test_setup_signatures(self, mock_detection_engine):
        pass

    def test_analyse_packet(self, mock_detection_engine, mock_packet):
        pass