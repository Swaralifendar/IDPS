import pydivert
from trafficevent import packet_to_event

with pydivert.WinDivert("true") as w:
    print("NIDS traffic capture started...\n")

    for packet in w:
        event = packet_to_event(packet)

        print(event)
        print("Payload:", event.payload[:100])
        print()

        # Reinject the original packet so traffic continues normally
        w.send(packet)