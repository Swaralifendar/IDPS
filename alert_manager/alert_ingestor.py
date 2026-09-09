from pathlib import Path
import json
# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

HIDS_LOG = BASE_DIR / "IDSIPS" / "logs" / "event.json"
NIDS_LOG = r"C:\Users\aishwaryarao.pantula\Downloads\IDPS\NIDS\EVE.json"

OUTPUT_FILE = BASE_DIR / "ingested_alerts.json"


# ============================================================
# ALERT INGESTION
# ============================================================

class AlertIngestion:

    def __init__(self, hids_path, nids_path):
        self.hids_path = Path(hids_path)
        self.nids_path = Path(nids_path)

    # --------------------------------------------------------
    # Read JSON Lines file
    # --------------------------------------------------------

    def read_json_lines(self, file_path):

        events = []

        if not file_path.exists():
            print(f"[!] File not found: {file_path}")
            return events

        with open(file_path, "r", encoding="utf-8") as f:

            for line_number, line in enumerate(f, start=1):

                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                except json.JSONDecodeError as e:
                    print(
                        f"[!] Invalid JSON in "
                        f"{file_path.name} at line {line_number}: {e}"
                    )
                    continue

                events.append(event)

        return events

    # --------------------------------------------------------
    # HIDS ALERT INGESTION
    # --------------------------------------------------------

    def ingest_hids(self):

        events = self.read_json_lines(self.hids_path)

        alerts = []

        for event in events:

            # HIDS alert format:
            # "type": "alert"

            if event.get("type") != "alert":
                continue

            alerts.append({
                "source": "HIDS",
                "data": event
            })

        return alerts

    # --------------------------------------------------------
    # NIDS ALERT INGESTION
    # --------------------------------------------------------

    def ingest_nids(self):

        events = self.read_json_lines(self.nids_path)

        alerts = []

        for event in events:

            # NIDS alert format:
            # "event_type": "alert"

            if event.get("event_type") != "alert":
                continue

            nested_alerts = event.get("alerts", [])

            # ------------------------------------------------
            # NIDS normally contains alerts inside alerts[]
            # ------------------------------------------------

            if nested_alerts:

                for nested_alert in nested_alerts:

                    alerts.append({
                        "source": "NIDS",

                        # Common packet information
                        "event": {
                            "timestamp": event.get("timestamp"),
                            "direction": event.get("direction"),
                            "src_ip": event.get("src_ip"),
                            "src_port": event.get("src_port"),
                            "dest_ip": event.get("dest_ip"),
                            "dest_port": event.get("dest_port"),
                            "proto": event.get("proto"),
                            "packet_size": event.get("packet_size"),
                            "payload_size": event.get("payload_size"),
                            "src_home_net": event.get("src_home_net"),
                            "dest_home_net": event.get("dest_home_net")
                        },

                        # Individual NIDS rule alert
                        "data": nested_alert
                    })

            else:

                # ------------------------------------------------
                # Fallback if an NIDS alert has no alerts[]
                # ------------------------------------------------

                alerts.append({
                    "source": "NIDS",
                    "data": event
                })

        return alerts

    # --------------------------------------------------------
    # INGEST BOTH HIDS AND NIDS
    # --------------------------------------------------------

    def ingest(self):

        hids_alerts = self.ingest_hids()
        nids_alerts = self.ingest_nids()

        return hids_alerts + nids_alerts


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("[*] ALERT INGESTION STARTED")
    print("=" * 80)

    print(f"[*] HIDS source : {HIDS_LOG}")
    print(f"[*] NIDS source : {NIDS_LOG}")
    print(f"[*] Output      : {OUTPUT_FILE}")
    print()

    # --------------------------------------------------------
    # Create ingestion object
    # --------------------------------------------------------

    ingestion = AlertIngestion(
        hids_path=HIDS_LOG,
        nids_path=NIDS_LOG
    )

    # --------------------------------------------------------
    # Collect alerts
    # --------------------------------------------------------

    alerts = ingestion.ingest()

    # --------------------------------------------------------
    # Write alerts as JSON Lines
    # --------------------------------------------------------

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        for alert in alerts:

            json.dump(
                alert,
                f,
                separators=(",", ":")
            )

            f.write("\n")

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    hids_count = sum(
        1
        for alert in alerts
        if alert["source"] == "HIDS"
    )

    nids_count = sum(
        1
        for alert in alerts
        if alert["source"] == "NIDS"
    )

    print("[+] Alert ingestion completed")
    print()
    print(f"    HIDS alerts  : {hids_count}")
    print(f"    NIDS alerts  : {nids_count}")
    print(f"    Total alerts : {len(alerts)}")
    print()
    print(f"[+] Output written to:")
    print(f"    {OUTPUT_FILE}")
    print("=" * 80)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()