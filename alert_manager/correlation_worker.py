from alert_manager.adapters.hids_adapter import HIDSAdapter
from alert_manager.adapters.nids_adapter import NIDSAdapter
from alert_manager.correlation_engine import CorrelationEngine
from paths import (
    ALERT_MANAGER_HIDS_CHECKPOINT_FILE,
    ALERT_MANAGER_NIDS_CHECKPOINT_FILE,
    CORRELATION_STATE_FILE,
    HIDS_EVENTS_FILE,
    NIDS_ALERTS_FILE,
)
from stop_signal import wait_for_stop


def main():

    hids = HIDSAdapter(
        log_path=HIDS_EVENTS_FILE,
        checkpoint_path=ALERT_MANAGER_HIDS_CHECKPOINT_FILE,
    )

    nids = NIDSAdapter(
        alerts_path=NIDS_ALERTS_FILE,
        checkpoint_path=ALERT_MANAGER_NIDS_CHECKPOINT_FILE,
    )

    # Correlation buckets, so event counts survive restarts
    engine = CorrelationEngine(
        state_file=CORRELATION_STATE_FILE
    )

    engine.load_state()

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

            engine.save_state()

        except Exception as e:
            print(f"[CORRELATION WORKER ERROR] {e}")

        # Sleep 1 s, or exit as soon as the service stops
        if wait_for_stop(1):
            break

    engine.save_state()

    print("[*] Correlation Worker stopped.")


if __name__ == "__main__":
    main()
