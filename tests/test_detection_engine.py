import pytest
from unittest.mock import MagicMock
from src.detection_engine import DetectionEngine 

@pytest.fixture
def mock_config():
    #TBD
    return {}

@pytest.fixture
def mock_detection_engine(mock_config):
    return DetectionEngine(config=mock_config)


class TestDetectionEngine:

    def test_initialise_instance(self, mock_config):
        """
        Verifies that detection engine intiialise with a correct config.
        """
        engine = DetectionEngine(config=mock_config)

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