import os
import sys

action = sys.argv[1] if len(sys.argv) > 1 else "trip"
FLAG_FILE = "trip_trigger.flag"

if action.lower() == "reset":
    if os.path.exists(FLAG_FILE):
        os.remove(FLAG_FILE)
        print("[RESET] Grid Breaker Restored -> Normal Line Power Restored.")
    else:
        print("Grid is already in Normal state.")
else:
    with open(FLAG_FILE, "w") as f:
        f.write("TRIPPED")
    print("[EMERGENCY TRIP] Main Breaker Tripped! DNP3 Command Rate Spiked to 20/s & UPS Battery Discharge Fired!")
