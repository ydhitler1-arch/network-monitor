"""Entry point — starts the API server (via waitress) and the background monitor thread."""

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waitress import serve  # noqa: E402

from backend import config  # noqa: E402
from backend.app import app, start_background_monitor  # noqa: E402

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config.warn_startup()
    start_background_monitor()
    print(f"Network Monitor serving on http://{config.HOST}:{config.PORT}")
    serve(app, host=config.HOST, port=config.PORT)
