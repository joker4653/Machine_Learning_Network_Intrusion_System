import multiprocessing as p
from multiprocessing import Queue

class DetectionEngine:
    """
    Primary Engine which handles passing data into detection modules.
    Spins a thread for network monitoring.
    Starts modules based on config file.

    Args: 
        config (dict[str, any]): Configuration files for the detection engine, contains settings and directory for signatures.

    Returns:
        None
    """
    def __init__(self, config: dict, input_queue: Queue) -> None:
        if config is None:
            print("Config cannot be None")
            raise ValueError("Config cannot be None")
        
        self.config = config
        self.queue = input_queue
        #self.network_thread = p.Process(target=network.network_monitor, args=(self.config["network_interface"])) TODO
        #self.signatures = self.load_signatures(self.config["signature_directory"]) TODO

        def stop(self):
            """
            stops all existing threads and closing modules.

            Returns:
                True if successful
                False if unsuccessful
            """

        def load_signatures(self, directory: str) -> dict:
            """
            Loads Signatures from a directory.

            Args:
                directory (str): Directory where signatures are stored.

            Returns:
                dict: Dictionary of signatures loaded from files.
            """
            return {}


        def analyse_packet(self, packet: dict) -> bool:
            """
            Passes a packet to all detection modules for analysis
            
            Args:
                packet Dict(str, str): Where key is the type of information i.e. 'src_ip' and value is the actual information i.e. 192.168.2.110

            Returns:
                True if malicious
                False if benign
            """

            return False
        
