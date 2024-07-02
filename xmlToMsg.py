import xml.etree.ElementTree as ET
import json

def parse_xml_to_json(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    json_output = []

    for weakness in root.findall(".//Weaknesses/Weakness"):
        code_snippet = ""
        vulnerability_info = {}

        for elem in weakness.iter():
            if elem.tag == "Body_Text":
                code_snippet += elem.text.strip() + "\n"
            elif elem.tag == "Extended_Description":
                vulnerability_info["Extended_Description"] = elem.text.strip()
            elif elem.tag == "Likelihood_Of_Exploit":
                vulnerability_info["Likelihood_Of_Exploit"] = elem.text.strip()
            elif elem.tag == "Detection_Methods":
                method = elem.find("Detection_Method")
                if method is not None:
                    method_text = method.find("Method").text
                    vulnerability_info["Detection_Methods"] = method_text.strip() if method_text is not None else ""
            elif elem.tag == "Potential_Mitigations":
                mitigation = elem.find("Mitigation")
                if mitigation is not None:
                    mitigation_info = {
                        "Phase": mitigation.find("Phase").text.strip() if mitigation.find("Phase") is not None else "",
                        "Description": mitigation.find("Description").text.strip() if mitigation.find("Description") is not None else "",
                        "Effectiveness": mitigation.find("Effectiveness").text.strip() if mitigation.find("Effectiveness") is not None else "",
                        "Effectiveness_Notes": mitigation.find("Effectiveness_Notes").text.strip() if mitigation.find("Effectiveness_Notes") is not None else ""
                    }
                    vulnerability_info["Potential_Mitigations"] = mitigation_info

        json_output.append(
            {
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
        )

    return json_output

import json

def save_jsonl(json_output, jsonl_file):
    with open(jsonl_file, 'w') as f:
        for entry in json_output:
            f.write(json.dumps(entry) + '\n')



# Example usage:
xml_file = "example.xml"  # Path to your XML file
json_output = parse_xml_to_json(xml_file)
print(json.dumps(json_output, indent=2))

# Example usage:
jsonl_file = "output.jsonl"  # Path to your JSONL file
save_jsonl(json_output, jsonl_file)