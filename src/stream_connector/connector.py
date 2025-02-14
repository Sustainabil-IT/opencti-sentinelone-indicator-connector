import re
import requests
import json
import time
import threading

from pycti import OpenCTIConnectorHelper
from config_variables import ConfigConnector
from s1_client import S1Client

MAX_BUFFER_SIZE = 20
SENDOFF_TIME = 5



PATTERN_RE =r"(?:file:hashes\.('SHA-256'|'SHA-1'|MD5)|url:value|ipv4-addr:value|domain-name:value|hostname:value)\s*[:=]\s*['\"]([^'\"]+)['\"]"


class IndicatorStreamConnector:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.s1_client = S1Client(self.config, self.helper)
        self.buffer = []
        self.last_indicator_time = time.time()
        self.buffer_lock = threading.Lock()  # Add thread safety
        self.helper.log_debug("Initialised Connector.")



    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")



    def check_buffer_periodically(self):
        """
        Periodically check if buffer needs to be sent due to time threshold
        """
        while True:
            time.sleep(1)  # Check every second
            current_time = time.time()
            with self.buffer_lock:
                if (len(self.buffer) > 0 and 
                    current_time - self.last_indicator_time > SENDOFF_TIME):
                    self.helper.log_info(
                        f"No new indicators in the last {SENDOFF_TIME} seconds, "
                        f"sending off buffer of size {len(self.buffer)}."
                    )
                    self.send_buffer()
                    self.buffer.clear()

    def process_message(self, msg) -> None:
        """
        Process incoming messages from the stream
        :param msg: Message object containing event and data
        :return: None
        """
        try:
            self.check_stream_id()
        except Exception:
            raise ValueError("Cannot process the message")

        current_time = time.time()
        if msg.event == "create":
            message_dict = json.loads(msg.data)
            if "creates a Indicator" in message_dict["message"]:
                self.helper.log_debug("New indicator to process found.")
                with self.buffer_lock:  # Add thread safety
                    if self.process_indicator(message_dict):
                        self.last_indicator_time = current_time
                    
                    if (len(self.buffer) >= MAX_BUFFER_SIZE):
                        self.helper.log_info(
                            f"Buffer of Indicators reached count of {MAX_BUFFER_SIZE}, "
                            "sending to SentinelOne."
                        )
                        self.send_buffer()
                        self.buffer.clear()

    def send_buffer(self) -> bool:
        """
        Send the buffer to SentinelOne
        :return: bool: True if buffer was sent successfully, False if send failed
        """
        self.helper.log_info(f"Attempting to send buffer of Indicators to SentinelOne")

        payload = self.s1_client.create_payload(self.buffer)
        if self.s1_client.send_buffer(payload):
            self.helper.log_info(f"Buffer of Indicators sent successfully to SentinelOne")
            time.sleep(3)
            return True
        else:
            self.helper.log_error(f"Buffer of Indicators failed to send to SentinelOne")
            return False

    def process_indicator(self, message_dict) -> bool:
        """
        :param message_dict: Dictionary containing message data.
        :return: bool: True if indicator was processed successfully, False if not
        """
        ioc_type = None
        ioc_value = None

        for extension_id, extension_data in message_dict.get("data",{}).get("extensions",{}).items():
            # Get observable_values list, default to empty list if not found
            observable_values_list = extension_data.get("observable_values", [])
            # Only process if list is not empty
            if observable_values_list:
                observable_values = observable_values_list[0]
                ioc_type, ioc_value = self.extract_indicator_type_value(observable_values)
                if ioc_type is not None and ioc_value is not None:
                    break

        if ioc_type is None or ioc_value is None:
            self.helper.log_info("IOC is of an unsupported type, skipping.")
            return False

        indicator_data = message_dict.get("data",{})
        payload = self.create_indicator_payload(indicator_data, ioc_type, ioc_value)
        self.buffer.append(payload)
        self.helper.log_info(f"IOC extracted successfully, added to buffer of size: {len(self.buffer)}")
        time.sleep(0.3)
        return True

    def create_indicator_payload(self, indicator_data, ioc_type, ioc_value) -> dict:
        """
        Create payload dictionary from indicator data
        :param indicator_data: Dictionary containing raw indicator data
        :param ioc_type: String containing the type of indicator
        :param ioc_value: String containing the value of indicator
        :return: dict: Formatted payload with valid entries
        """
        possible_entries = {
            "type": ioc_type,
            "value": ioc_value,

            #TODO: maybe implmeent determination method
            "method": "EQUALS",

            "name": indicator_data.get("name"),
            "description": indicator_data.get("description"),
            "externalId": indicator_data.get("id"),

            "pattern": indicator_data.get("pattern"),
            "patternType": indicator_data.get("pattern_type"),

            ###FIX
            "labels": indicator_data.get("labels"),


            "source": self.config.connector_name,
            "validUntil": indicator_data.get("valid_until"),
            "creationTime": indicator_data.get("created"),

            ###FIX
            "creator": "OpenCTI Indicator Stream Connector"

        }
        valid_entries = {k: v for k, v in possible_entries.items() if v is not None}
        return valid_entries

    def extract_indicator_type_value(self, observable_values) -> tuple[str, str]:
        """
        Extract indicator type and value from observable values
        :param observable_values: Dictionary containing observable values
        :return: tuple[str, str]: Indicator type and value, or (None, None) if not found
        """
        indicator_type = None
        indicator_value = None
        
        val = observable_values.get("hashes",{}).get("SHA-1")
        if val:
            indicator_type = "SHA1"
            indicator_value = val

        val =  observable_values.get("hashes",{}).get("SHA-256")
        if val:
            indicator_type = "SHA256"
            indicator_value = val
        
        val =  observable_values.get("hashes",{}).get("MD5")
        if val:
            indicator_type = "MD5"
            indicator_value = val



        
        val =  observable_values.get("type","") == "IPv4-Addr"
        if val:
            indicator_type = "IPV4"
            indicator_value = observable_values.get("value","")
        
        val = observable_values.get("type","") == "Domain-Name"
        if val:
            indicator_type = "DNS"
            indicator_value = observable_values.get("value","")
        
        val =  observable_values.get("type","") == "Url"
        if val:
            indicator_type = "URL"
            indicator_value = observable_values.get("value","")

        return indicator_type, indicator_value

    """
    ##TODO: regex wont work for this logic. rewrite it.
    def extract_indicator_type_value_fallback(self, pattern) -> tuple[str, str]:

        match = re.search(PATTERN_RE, pattern)
        if not match:
            self.helper.log_debug(
                "Error, no Type and Value found for the IOC (regex failure)"
            )
        elif match.lastindex != 2:
            self.helper.log_debug(
                "Error, no Type and Value found for the IOC (regex failure)"
            )
            self.helper.log_debug(
                f"regex search attempt resulted in: ({", ".join(match.groups())})"
            )
        else:
            self.helper.log_debug("Success, Type and Value found in pattern.")
            ioc_value = match.group(2).strip('"').strip("]").strip("'")
            try:
                ioc_type = S1_CONVERSIONS[match.group(1)]

                self.helper.log_debug(pattern)

                self.helper.log_debug("Success, Type converted to SentinelOne format.")
                return ioc_type, ioc_value
            except KeyError:
                # Handle unsupported key
                unsupported_type = match.group(1)
                self.helper.log_error(
                    f"Unsupported Type: '{unsupported_type}' found in pattern. Type is not supported by SentinelOne."
                )
            except Exception as e:
                # Keep other exception handling
                self.helper.log_error(f"Error converting Type, Exception Error: {e}")

        return (None, None)

    """


                
    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        # Start the buffer checking thread
        buffer_thread = threading.Thread(
            target=self.check_buffer_periodically, 
            daemon=True
        )
        buffer_thread.start()
        
        # Start listening for messages
        self.helper.listen_stream(message_callback=self.process_message)


if __name__ == "__main__":
    connector = IndicatorStreamConnector()
    connector.run()