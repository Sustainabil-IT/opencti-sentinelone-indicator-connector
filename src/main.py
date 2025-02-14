import traceback

from stream_connector import IndicatorStreamConnector

if __name__ == "__main__":
    try:
        connector = IndicatorStreamConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
