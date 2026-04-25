import sniffer
import threading
from logger import AlertLogger
from detector import Detector

logger = AlertLogger()
detector = Detector(logger)
s = sniffer.PacketSniffer(detector, logger)

def run():
    print("Sniffer thread starting...")
    try:
        s.start()
    except Exception as e:
        print("Error:", e)
    print("Sniffer thread ended.")

t = threading.Thread(target=run)
t.start()
t.join()
