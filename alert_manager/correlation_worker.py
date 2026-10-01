import time

from alert_manager.adapters.hids_adapter import HIDSAdapter
from alert_manager.adapters.nids_adapter import NIDSAdapter
from alert_manager.correlation_engine import CorrelationEngine


def main():

    hids = HIDSAdapter(
        log_path="logs/event.json",
        checkpoint_path="logs/alert_manager_hids_checkpoint.json",
    )

    nids = NIDSAdapter(
        alerts_path="NIDS/alerts.json",
        checkpoint_path="logs/alert_manager_nids_checkpoint.json",
    )

    engine = CorrelationEngine()

    print("[*] Correlation Worker started.")

    while True:
        try:

            hids_events = hids.read_new_alerts()

            for event in hids_events:
                print(
                    f"[HIDS] "
                    f"Category={event.category_type} "
                    f"Source={event.source_ip} "
                    f"Host={event.host_ip}"
                )

                engine.process_event(event)

            nids_events = nids.read_new_alerts()

            for event in nids_events:
                print(
                    f"[NIDS] "
                    f"Category={event.category_type} "
                    f"Source={event.source_ip} "
                    f"Destination={event.destination_ip}"
                )

                engine.process_event(event)

            engine.cleanup()

            time.sleep(1)

        except Exception as e:
            print(f"[CORRELATION WORKER ERROR] {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()