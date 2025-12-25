CONTAMINATION_FACTOR = 0.1

ANOMALY_THRESHOLD_LOW = 0.5
ANOMALY_THRESHOLD_MEDIUM = 0.6
ANOMALY_THRESHOLD_HIGH = 0.8

RANDOM_STATE = 42

PORT_SCAN_THRESHOLD_MEDIUM = 20
PORT_SCAN_THRESHOLD_HIGH = 50

HIGH_VOLUME_THRESHOLD = 1_000_000

HIGH_RATE_THRESHOLD = 100

FLOW_TIMEOUT = 60

MIN_PACKETS_PER_FLOW = 3

DEFAULT_CAPTURE_COUNT = 1000

DEFAULT_CAPTURE_TIMEOUT = 60

DEFAULT_INTERFACE = None

DEFAULT_BPF_FILTER = ""

ALERTS_LOG_PATH = "reports/alerts.log"

ALERTS_JSON_PATH = "reports/alerts.json"

CONSOLE_OUTPUT_FORMAT = "detailed"

ENABLE_COLORED_OUTPUT = True

MODEL_SAVE_PATH = "model/trained_model.pkl"

AUTO_SAVE_MODEL = True

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP"
}

SEVERITY_LEVELS = {
    "LOW": {
        "color": "\033[93m",
        "prefix": "[LOW]",
        "priority": 1
    },
    "MEDIUM": {
        "color": "\033[33m",
        "prefix": "[MEDIUM]",
        "priority": 2
    },
    "HIGH": {
        "color": "\033[91m",
        "prefix": "[HIGH]",
        "priority": 3
    }
}

COLOR_RESET = "\033[0m"

DEMO_NORMAL_FLOWS = 100

DEMO_ANOMALY_FLOWS = 10
