import logging
from pathlib import Path


# Project root directory
BASE_DIR = Path(__file__).resolve().parent

# Directory where log files will be stored
LOG_DIR = BASE_DIR / "logs"

# Create the logs directory if it doesn't exist
LOG_DIR.mkdir(exist_ok=True)

# Log file
LOG_FILE = LOG_DIR / "idsips.log"


def get_logger():
    logger = logging.getLogger("IDSIPS")

    # Prevent duplicate handlers if get_logger() is called more than once
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # Write logs to file
    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger