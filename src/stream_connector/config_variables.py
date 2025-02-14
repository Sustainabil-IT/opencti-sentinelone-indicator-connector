import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        self.load = self._load_config()
        self._initialize_configurations()


    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """

        #config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config_file_path = "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config


    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables with validation
        :return: None
        :raises ValueError: If any required configuration is missing or invalid
        """
        # Helper function to validate config
        def validate_config(value: str, name: str) -> str:
            if not value:
                raise ValueError(f"Missing required configuration: {name}")
            return value

        try:
            # Connector configurations
            self.connector_name = validate_config(
                get_config_variable("CONNECTOR_NAME", ["connector", "name"], self.load),
                "connector_name"
            )


            # SentinelOne configurations
            self.s1_url = validate_config(
                get_config_variable("SENTINELONE_URL", ["sentinelOne", "url"], self.load),
                "sentinelOne_url"
            )

            self.s1_api_key = "APIToken " + validate_config(
                get_config_variable("SENTINELONE_API_KEY", ["sentinelOne", "api_key"], self.load),
                "sentinelOne_api_key"
            )

            self.s1_account_id = validate_config(
                get_config_variable("SENTINELONE_ACCOUNT_ID", ["sentinelOne", "account_id"], self.load),
                "sentinelOne_account_id"
            )


            # Validate max_api_attempts is a positive integer
            max_attempts = get_config_variable(
                "SENTINELONE_MAX_API_ATTEMPTS",
                ["sentinelOne", "max_api_attempts"],
                self.load,
            )
            if not max_attempts or not str(max_attempts).isdigit() or int(max_attempts) <= 0:
                raise ValueError("max_api_attempts must be a positive integer")
            self.max_api_attempts = int(max_attempts)

        except Exception as e:
            raise ValueError(f"Configuration error: {str(e)}")
