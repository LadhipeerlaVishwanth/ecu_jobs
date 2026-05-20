
import csv
from collections import defaultdict

grouped_cases = defaultdict(list)

def clean_expected_response(resp):

    if not resp:
        return []

    raw_bytes = resp.strip().split()

    cleaned = []

    for i, b in enumerate(raw_bytes):

        b = b.upper()

        # Remove padding bytes
        if b == "AA":
            continue

        # Remove ISO-TP frame length / PCI bytes
        if i == 0 and b in ["10", "21", "22", "06", "07", "08"]:
            continue

        # Remove second byte after 10 (length byte)
        if i == 1 and raw_bytes[0].upper() == "10":
            continue

        cleaned.append(int(b, 16))

    return cleaned

def load_testcases(file_path):
       
    grouped_cases.clear()
    try:
        with open(file_path, "r") as f:
            reader = csv.reader(f)
            header = next(reader)  # Skip header

            for row in reader:
                if not row or len(row) < 5:
                    continue  # Skip empty or malformed lines

                tc_id = row[0].strip()
                step_desc = row[1].strip()
                service_id = row[2].strip()
                subfunction_or_did = row[3].strip()
                expected_response = clean_expected_response(row[4].strip())
                write_data = row[5].strip() if len(row) > 5 else ""
                addressing = row[6].strip().lower() if len(row) > 6 else "physical"


                grouped_cases[tc_id].append((
                    tc_id,
                    step_desc,
                    service_id,
                    subfunction_or_did,
                    expected_response,
                    write_data,
                    addressing
                ))

        return grouped_cases

    except Exception as e:
        print(f"Error parsing testcases: {e}")
        return {}
