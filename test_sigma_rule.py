from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

log_file = (
    "data/raw/EVTX-ATTACK-SAMPLES/Execution/"
    "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
)

matches = 0

with Evtx(log_file) as log:
    for number, record in enumerate(log.records(), start=1):

        root = ET.fromstring(record.xml())

        # Remove XML namespace
        for element in root.iter():
            if "}" in element.tag:
                element.tag = element.tag.split("}", 1)[1]

        system = root.find("System")
        event_id = system.findtext("EventID") if system is not None else None

        # Our Sigma rule is for process creation
        if event_id != "1":
            continue

        event_data = root.find("EventData")

        fields = {}

        if event_data is not None:
            for field in event_data.findall("Data"):
                fields[field.attrib.get("Name", "")] = field.text or ""

        image = fields.get("Image", "")
        command_line = fields.get("CommandLine", "")

        # Same logic as our Sigma rule
        image_match = image.lower().endswith("\\rundll32.exe")
        command_match = "javascript:" in command_line.lower()

        if image_match and command_match:
            matches += 1

            print("\n=== SIGMA RULE MATCH ===")
            print("Event number:", number)
            print("Event ID:", event_id)
            print("Image:", image)
            print("CommandLine:", command_line)

print("\nTotal matches:", matches)