
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

log_file = (
    "data/raw/EVTX-ATTACK-SAMPLES/Execution/"
    "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
)

matches = {
    "Rule 1 - Suspicious Rundll32 JavaScript": 0,
    "Rule 2 - Suspicious Mshta Remote URL": 0,
}

with Evtx(log_file) as log:
    for number, record in enumerate(log.records(), start=1):
        root = ET.fromstring(record.xml())

        # Remove XML namespaces
        for element in root.iter():
            if "}" in element.tag:
                element.tag = element.tag.split("}", 1)[1]

        system = root.find("System")
        event_id = (
            system.findtext("EventID")
            if system is not None
            else None
        )

        # Both rules target process-creation events
        if event_id != "1":
            continue

        event_data = root.find("EventData")
        fields = {}

        if event_data is not None:
            for field in event_data.findall("Data"):
                fields[field.attrib.get("Name", "")] = field.text or ""

        image = fields.get("Image", "")
        command_line = fields.get("CommandLine", "")

        # Rule 1: rundll32.exe + javascript:
        if (
            image.lower().endswith("\\rundll32.exe")
            and "javascript:" in command_line.lower()
        ):
            matches["Rule 1 - Suspicious Rundll32 JavaScript"] += 1
            print(f"\nRule 1 matched event {number}")
            print("Image:", image)
            print("CommandLine:", command_line)

        # Rule 2: mshta.exe + HTTP/HTTPS URL
        if (
            image.lower().endswith("\\mshta.exe")
            and (
                "http://" in command_line.lower()
                or "https://" in command_line.lower()
            )
        ):
            matches["Rule 2 - Suspicious Mshta Remote URL"] += 1
            print(f"\nRule 2 matched event {number}")
            print("Image:", image)
            print("CommandLine:", command_line)

print("\n=== TEST SUMMARY ===")
for rule, count in matches.items():
    print(f"{rule}: {count} match(es)")
