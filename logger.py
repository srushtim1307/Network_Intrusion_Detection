# ============================================================
#  logger.py  –  Network IDS  |  Alert Logger
# ============================================================
#  Handles writing alerts to both the console and a log file.
#  Import AlertLogger anywhere you need to fire an alert.
# ============================================================

import logging
import os
from datetime import datetime
from config import LOG_FILE, LOG_TO_CONSOLE


class AlertLogger:
    """
    Simple logger that writes timestamped alerts to:
      • the terminal  (coloured, if supported)
      • alerts.log    (plain text, append mode)
    """

    # ANSI colour codes for terminal output
    COLOURS = {
        "RED"    : "\033[91m",
        "YELLOW" : "\033[93m",
        "GREEN"  : "\033[92m",
        "CYAN"   : "\033[96m",
        "RESET"  : "\033[0m",
    }

    def __init__(self):
        self._setup_file_logger()
        self.alert_count = 0       # running total of alerts fired

    # ── Private helpers ───────────────────────────────────

    def _setup_file_logger(self):
        """Configure Python's logging module to write to LOG_FILE."""
        logging.basicConfig(
            filename  = LOG_FILE,
            filemode  = "a",          # append so old alerts aren't lost
            level     = logging.INFO,
            format    = "%(asctime)s  |  %(levelname)-8s  |  %(message)s",
            datefmt   = "%Y-%m-%d %H:%M:%S",
        )
        self.file_logger = logging.getLogger("IDS")

    def _colour(self, text: str, colour: str) -> str:
        """Wrap text in ANSI colour codes (graceful if unsupported)."""
        c = self.COLOURS.get(colour.upper(), "")
        r = self.COLOURS["RESET"]
        return f"{c}{text}{r}"

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Public API ────────────────────────────────────────

    def alert(self, alert_type: str, message: str, severity: str = "HIGH"):
        """
        Fire an alert.

        Parameters
        ----------
        alert_type : str  – short category label, e.g. "PORT_SCAN"
        message    : str  – human-readable description
        severity   : str  – "HIGH" | "MEDIUM" | "LOW"
        """
        self.alert_count += 1

        colour_map = {"HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "CYAN"}
        colour     = colour_map.get(severity.upper(), "YELLOW")

        full_message = (
            f"[ALERT #{self.alert_count}] "
            f"[{severity}] "
            f"[{alert_type}] "
            f"{message}"
        )

        # Write to log file (no ANSI codes)
        self.file_logger.warning(full_message)

        # Print to terminal with colour
        if LOG_TO_CONSOLE:
            print(self._colour(f"  ⚠  {full_message}", colour))

    def info(self, message: str):
        """Log a non-alert informational message (green, no alert label)."""
        self.file_logger.info(f"[INFO] {message}")
        if LOG_TO_CONSOLE:
            print(self._colour(f"  ✓  {message}", "GREEN"))

    def separator(self):
        """Print a visual separator line to the terminal."""
        if LOG_TO_CONSOLE:
            print(self._colour("─" * 70, "CYAN"))

    def summary(self):
        """Print / log a final summary when the sniffer stops."""
        msg = f"Session complete. Total alerts generated: {self.alert_count}"
        self.file_logger.info(msg)
        if LOG_TO_CONSOLE:
            self.separator()
            print(self._colour(f"  📋  {msg}", "CYAN"))
            print(self._colour(f"  📁  Log saved to: {os.path.abspath(LOG_FILE)}", "CYAN"))
            self.separator()
