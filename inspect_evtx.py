
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

log_file = (
    "data/raw/EVTX-ATTACK-SAMPLES/Execution/"
    "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
)

with Evtx(log_file) as log:
    for number, record in enumerate(log.records()):
        if number >= 5:
            break

        root = ET.fromstring(record.xml())

        # Remove the XML namespace for simpler field access
        for element in root.iter():
            if "}" in element.tag:
                element.tag = element.tag.split("}", 1)[1]

        system = root.find("System")
        event_id = system.findtext("EventID") if system is not None else None

        time_element = system.find("TimeCreated") if system is not None else None
        timestamp = (
            time_element.attrib.get("SystemTime")
            if time_element is not None
            else None
        )

        provider = system.find("Provider") if system is not None else None
        provider_name = (
            provider.attrib.get("Name")
            if provider is not None
            else None
        )

        print(f"\n--- Event {number + 1} ---")
        print("Event ID:", event_id)
        print("Timestamp:", timestamp)
        print("Provider:", provider_name)

        event_data = root.find("EventData")
        if event_data is not None:
            for field in event_data.findall("Data"):
                print(f"{field.attrib.get('Name', 'Unnamed field')}: {field.text}")
