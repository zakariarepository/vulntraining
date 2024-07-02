import xml.etree.ElementTree as ET
import json

def parse_xml_to_json(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    code_snippet = ""
    vulnerability_info = {}

    for elem in root.iter():
        if elem.tag == "Body_Text":
            code_snippet += elem.text.strip() + "\n"
        elif elem.tag == "Extended_Description":
            vulnerability_info["Extended_Description"] = elem.text.strip()
        elif elem.tag == "Likelihood_Of_Exploit":
            vulnerability_info["Likelihood_Of_Exploit"] = elem.text.strip()
        elif elem.tag == "Detection_Methods":
            for method in elem.iter("Detection_Method"):
                vulnerability_info["Detection_Methods"] = method.find("Method").text.strip()
        elif elem.tag == "Potential_Mitigations":
            for mitigation in elem.iter("Mitigation"):
                mitigation_info = {
                    "Phase": mitigation.find("Phase").text.strip(),
                    "Description": mitigation.find("Description").text.strip(),
                    "Effectiveness": mitigation.find("Effectiveness").text.strip(),
                    "Effectiveness_Notes": mitigation.find("Effectiveness_Notes").text.strip()
                }
                vulnerability_info["Potential_Mitigations"] = mitigation_info

    json_output = {
        "messages": [
            {
                "role": "user",
                "content": code_snippet
            },
            {
                "role": "system",
                "content": vulnerability_info.get("Extended_Description", "")
            },
            {
                "role": "assistant",
                "content": f"Likelihood of Exploit: {vulnerability_info.get('Likelihood_Of_Exploit', '')}\nDetection Methods: {vulnerability_info.get('Detection_Methods', '')}\nPotential Mitigations: {json.dumps(vulnerability_info.get('Potential_Mitigations', ''))}"
            }
        ]
    }

    return json_output

# Example usage:
xml_file = "example.xml"  # Path to your XML file
json_output = parse_xml_to_json(xml_file)
print(json.dumps(json_output, indent=2))
