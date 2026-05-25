# drivers/report_generator.py

import os
import re
import datetime
from collections import defaultdict
from html import escape

from drivers.config_loader import load_config

config = load_config()

DESCRIPTION_MAP = config["uds"]["reporting"].get("description_map", {})
ALLOWED_IDS = set(config["uds"]["reporting"].get("allowed_ids", []))


def load_description_map(txt_file_path):
    desc_map = {}
    with open(txt_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.lower().startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue
            tc_id = parts[0].strip()
            description = parts[1].strip()
            sid = parts[2].strip().replace("0x", "").upper()
            sub = parts[3].strip().replace("0x", "").upper()
            expected_response_data = parts[4].strip()
            expected_bytes = [b.replace("0x", "").upper() for b in expected_response_data.split() if b]
            format_type = parts[7].strip().capitalize() if len(parts) > 7 else "Hex"
            key = (sid, sub)
            value = (description, tc_id, expected_bytes, format_type)
            if key not in desc_map:
                desc_map[key] = []
            desc_map[key].append(value)
    return desc_map


def parse_data_bytes(line):
    # Extract every standalone 2-hex byte on the line (works for your ASC format)
    return [b.upper() for b in re.findall(r'\b[0-9A-Fa-f]{2}\b', line)]


def get_description(data_bytes):
    if not data_bytes or len(data_bytes) < 1:
        return "", "", "", ""

    known_sids = {"10", "11", "22", "2E", "19", "27", "28", "2F", "3E", "31", "14", "85"}
    sid_index = -1
    sid = ""
    for i, byte in enumerate(data_bytes):
        if byte.upper() in known_sids:
            sid_index = i
            sid = byte.upper()
            break

    if sid_index == -1:
        return "", "", "", ""

    # Try subfunction/DID lengths 3, 2, 1, or SID only
    for length in (3, 2, 1, 0):
        if sid_index + length < len(data_bytes):
            sub = ''.join(data_bytes[sid_index + 1: sid_index + 1 + length]).upper() if length > 0 else ""
            key = (sid, sub)
            if key in DESCRIPTION_MAP:
                used = getattr(get_description, "used_tc_ids", set())
                for desc, tc_id, expected_resp, fmt in DESCRIPTION_MAP[key]:
                    if tc_id not in used:
                        used.add(tc_id)
                        setattr(get_description, "used_tc_ids", used)
                        return desc, tc_id, expected_resp, fmt
                return DESCRIPTION_MAP[key][0]

    key = (sid, "")
    if key in DESCRIPTION_MAP:
        used = getattr(get_description, "used_tc_ids", set())
        for desc, tc_id, expected_resp, fmt in DESCRIPTION_MAP[key]:
            if tc_id not in used:
                used.add(tc_id)
                setattr(get_description, "used_tc_ids", used)
                return desc, tc_id, expected_resp, fmt
        return DESCRIPTION_MAP[key][0]

    return "", "", "", ""


def get_failure_reason(nrc):
    reasons = {
        "10": "generalReject",
        "11": "serviceNotSupported",
        "12": "subFunctionNotSupported",
        "13": "incorrectMessageLengthOrInvalidFormat",
        "14": "responseTooLong",
        "21": "busyRepeatReques",
        "22": "conditionsNotCorrect",
        "23": "ISOSAEReserved",
        "24": "requestSequenceError",
        "31": "requestOutOfRange",
        "32": "ISOSAEReserved",
        "33": "securityAccessDenied",
        "34": "ISOSAEReserved",
        "35": "invalidKey",
        "36": "exceedNumberOfAttempts",
        "37": "requiredTimeDelayNotExpired",
        "70": "uploadDownloadNotAccepted",
        "71": "transferDataSuspended",
        "72": "generalProgrammingFailure",
        "73": "wrongBlockSequenceCounter",
        "78": "requestCorrectlyReceived-ResponsePending",
        "7E": "subFunctionNotSupportedInActiveSession",
        "7F": "serviceNotSupportedInActiveSession",
        "80": "ISOSAEReserved",
        "81": "rpmTooHigh",
        "82": "rpmTooLow",
        "83": "engineIsRunning",
        "84": "engineIsNotRunning",
        "85": "engineRunTimeTooLow",
        "86": "temperatureTooHigh",
        "87": "temperatureTooLow",
        "88": "vehicleSpeedTooHigh",
        "89": "vehicleSpeedTooLow",
        "8A": "throttle/PedalTooHigh",
        "8B": "throttle/PedalTooLow",
        "8C": "transmissionRangeNotInNeutral",
        "8D": "transmissionRangeNotInGear",
        "8E": "ISOSAEReserved",
        "8F": "brakeSwitch(es)NotClosed (Brake Pedal not pressed or not applied)",
        "90": "shifterLeverNotInPark",
        "91": "torqueConverterClutchLocked",
        "92": "voltageTooHigh",
        "93": "voltageTooLow",
        "FF": "ISOSAEReserved",
    }
    return reasons.get(nrc.upper(), f"Unknown NRC: {nrc}")


def strip_pci_byte(data):
    if not data:
        return data
    data = [b.strip().upper() for b in data if isinstance(b, str)]
    try:
        pci = int(data[0], 16)
        # Single-frame ISO-TP PCI: 01 to 07
        if 0x01 <= pci <= 0x07 and len(data) >= pci + 1:
            return data[1:pci + 1]
        # Multi-frame first frame: 10 length SID...
        if data[0] == "10" and len(data) >= 3:
            return data[2:]
    except Exception:
        pass
    return data


def get_status(actual_data, expected_response_data):
    """
    Determines Pass/Fail by comparing actual response payload vs expected response.
    Handles PCI bytes and negative responses.
    """
    if not actual_data:
        return "Fail", "No response received"
    if not expected_response_data:
        return "Fail", "Expected response not specified"

    actual_data = [b.strip().upper() for b in actual_data if isinstance(b, str)]
    expected_data = [b.strip().upper() for b in expected_response_data if isinstance(b, str)]

    actual_payload = strip_pci_byte(actual_data)
    expected_payload = strip_pci_byte(expected_data)

    if actual_payload == expected_payload:
        return "Pass", ""

    if len(actual_payload) >= 3 and actual_payload[0] == "7F":
        nrc = actual_payload[2]
        return "Fail", f"Negative Response (0x{nrc}: {get_failure_reason(nrc)})"
    return "Fail", f"Response mismatch. Expected: {' '.join(expected_payload)}, Got: {' '.join(actual_payload)}"


def parse_line(line):
    line = line.strip()
    if not line:
        return None
    # Require a timestamp at the start: "0.000000"
    if not re.match(r'^\d+\.\d+', line):
        return None
    parts = line.split()
    # Direction token case-insensitive
    direction_index = None
    for i, part in enumerate(parts):
        if part.upper() in ("TX", "RX"):
            direction_index = i
            break
    if direction_index is None or direction_index == 0:
        return None
    can_id = parts[direction_index - 1].strip()  # e.g., "706" or "70E"
    try:
        timestamp = float(parts[0])
    except Exception:
        return None
    direction = parts[direction_index].upper()  # "TX" or "RX"
    return {
        "timestamp": timestamp,
        "can_id": can_id,
        "direction": direction,
        "data_bytes": parse_data_bytes(line),
        "raw": line
    }

def basic_sid_sub(data):
    if not data:
        return "UNK", ""

    clean = strip_pci_byte(data)

    if len(clean) >= 1:
        sid = clean[0]

        if len(clean) >= 3:
            sub = ''.join(clean[1:3])
        elif len(clean) >= 2:
            sub = clean[1]
        else:
            sub = ""

        return sid, sub

    return "UNK", ""

def parse_asc_file(asc_file_path, allowed_tx_ids, allowed_rx_ids):
    messages_by_tc = defaultdict(list)
    current_request = None
    pending_first_frame = None
    assembling_request = False
    request_buffer = []
    total_req_len = 0

    awaiting_response = False
    response_buffer = []
    total_resp_len = 0
    collected_len = 0
    skip_next_fc = False
    pending_flag = False

    start_ts, end_ts = None, None
    base_datetime = None

    # Normalize allowed IDs to integers
    allowed_tx_ids_int = set(int(x) for x in allowed_tx_ids)
    allowed_rx_ids_int = set(int(x) for x in allowed_rx_ids)
    allowed_ids_int = allowed_tx_ids_int | allowed_rx_ids_int

    with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    # Parse "Begin Triggerblock ..." datetime if present
    for i, line in enumerate(lines):
        if line.startswith("Begin Triggerblock"):
            try:
                date_str = line.strip().replace("Begin Triggerblock ", "")
                base_datetime = datetime.datetime.strptime(date_str, "%a %b %d %I:%M:%S.%f %p %Y")
            except ValueError:
                base_datetime = None
            break

    for line in lines:
        line = line.strip()
        if not line or not re.match(r"^\d+\.\d+", line):
            continue

        msg = parse_line(line)
        if not msg:
            continue

        # Convert CAN ID text to int (hex preferred, decimal fallback)
        cid_text = msg["can_id"]
        try:
            cid_val = int(cid_text, 16)
        except ValueError:
            try:
                cid_val = int(cid_text, 10)
            except ValueError:
                continue

        if cid_val not in allowed_ids_int:
            continue

        direction = msg["direction"]  # "TX" or "RX"
        data = msg["data_bytes"]
        if not data:
            continue

        # TX: Handle Request
        if direction == "TX" and cid_val in allowed_tx_ids_int:
            pci_type = data[0].upper()

            if pci_type == "10":  # First Frame of Multi-Frame Request
                assembling_request = True
                total_req_len = ((int(data[0], 16) & 0x0F) << 8) + int(data[1], 16)
                request_buffer = data[2:]
                pending_first_frame = msg
                skip_next_fc = True
                continue

            elif skip_next_fc and pci_type == "30":  # Ignore Flow Control after our FF
                skip_next_fc = False
                continue

            elif assembling_request and pci_type.startswith("2"):  # Consecutive Frame
                request_buffer += data[1:]
                if len(request_buffer) >= total_req_len:
                    trimmed_data = request_buffer[:total_req_len]
                    desc, tc_id, expected_resp, fmt = get_description(trimmed_data)
                    if not (desc and tc_id):
                        sid, sub = basic_sid_sub(trimmed_data)
                        desc = f"UNMAPPED Request SID={sid} SUB={sub}"
                        tc_id = f"UNMAPPED_{sid}_{sub}"
                        expected_resp = []
                        fmt = "Hex"
                    current_request = {
                        "timestamp": pending_first_frame["timestamp"],
                        "can_id": f"{cid_val:X}",
                        "direction": "TX",
                        "data_bytes": trimmed_data,
                        "desc": desc,
                        "tc_id": tc_id,
                        "format": fmt,
                        "expected_resp": expected_resp,
                        "status": "Pending"
                    }
                    if start_ts is None:
                        start_ts = current_request["timestamp"]
                        
                    assembling_request = False
                    request_buffer = []
                    pending_first_frame = None

            else:# Single-Frame Request
                desc, tc_id, expected_resp, fmt = get_description(data)
                if not (desc and tc_id):
                    sid, sub = basic_sid_sub(data)
                    desc = f"UNMAPPED Request SID={sid} SUB={sub}"
                    tc_id = f"UNMAPPED_{sid}_{sub}"
                    expected_resp = []
                    fmt = "Hex"
                    
                current_request = {
                    "timestamp": msg["timestamp"],
                    "can_id": f"{cid_val:X}",
                    "direction": direction,
                    "data_bytes": data,
                    "desc": desc,
                    "tc_id": tc_id,
                    "format": fmt,
                    "expected_resp": expected_resp,
                    "status": "Pending"
                }

                if start_ts is None:
                    start_ts = current_request["timestamp"]

        # RX: Handle Response
        elif direction == "RX" and cid_val in allowed_rx_ids_int and current_request:
            pci_type = data[0].upper()

            if pci_type == "30":
                continue  # Ignore flow control

            # Handle 0x7F xx 78 pending response
            if len(data) >= 4 and data[1].upper() == "7F" and data[3].upper() == "78":
                pending_flag = True
                continue

            if pending_flag:
                pending_flag = False
                full_resp = data  # Treat next frame as actual response
            else:
                if pci_type == "10":  # First frame of multi-frame response
                    total_resp_len = ((int(data[0], 16) & 0x0F) << 8) + int(data[1], 16)
                    response_buffer = data[:]  # include full frame including PCI+LEN
                    collected_len = len(data) - 2  # count payload excluding PCI and LEN
                    awaiting_response = True
                    continue

                elif pci_type.startswith("2") and awaiting_response:
                    response_buffer += data[1:]  # add consecutive payload excluding PCI byte
                    collected_len += len(data) - 1
                    if collected_len >= total_resp_len:
                        full_resp = response_buffer
                        awaiting_response = False
                    else:
                        continue
                else:
                    if awaiting_response:
                        response_buffer += data[1:]
                        full_resp = response_buffer
                        awaiting_response = False
                    else:
                        full_resp = data

            # Evaluate response against expected
            status, reason = get_status(full_resp, current_request["expected_resp"])
            current_request.update({
                "response": msg,
                "response_data_bytes": full_resp,
                "status": status,
                "failure_reason": reason
            })

            messages_by_tc[current_request["tc_id"]].append(current_request)

            # Update timestamps
            if start_ts is None:
                start_ts = current_request["timestamp"]
            end_ts = max(end_ts or msg["timestamp"], msg["timestamp"])

            current_request = None
            response_buffer = []

    return messages_by_tc, start_ts or 0, end_ts or 0, base_datetime


def flatten_bytes(data):
    flat = []
    for item in data:
        if isinstance(item, list):
            flat.extend(item)
        else:
            flat.append(item)
    return flat


def remove_trailing_padding(data_list, pad_byte):
    # Remove only trailing occurrences of pad_byte (like "00" or "AA")
    i = len(data_list)
    while i > 0 and data_list[i - 1].upper() == pad_byte.upper():
        i -= 1
    return data_list[:i]


def get_valid_request_data(data_bytes):
    """
    Extracts the actual data from a UDS request.
    Assumes the first byte is the PCI, which tells us how many bytes follow.
    """
    if not data_bytes:
        return data_bytes
    try:
        pci = int(data_bytes[0], 16)
        if pci <= 0x07:  # single-frame: first byte is length of remaining data
            total_len = pci + 1  # include PCI itself
            return data_bytes[:total_len]
    except:
        pass
    return data_bytes


def generate_html_report(messages_by_tc, output_path, asc_filename, start_ts, end_ts, ecu_info_data=None, target_ecu=None, base_datetime=None):
    def remove_padding(data_list, pad_byte):
        return [byte for byte in data_list if byte.upper() != pad_byte.upper()]

    total = len(messages_by_tc)
    passed = sum(1 for tc in messages_by_tc.values() if all(msg["status"] == "Pass" for msg in tc))
    failed = total - passed
    duration = end_ts - start_ts
    generated_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format Start_Timestamp and End_Timestamp
    if base_datetime:
        start_dt = base_datetime + datetime.timedelta(seconds=start_ts)
        end_dt = base_datetime + datetime.timedelta(seconds=end_ts)
        Start_Timestamp = start_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        End_Timestamp = end_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    else:
        Start_Timestamp = f"{start_ts:.3f} seconds"
        End_Timestamp = f"{end_ts:.3f} seconds"

    html = f"""<!DOCTYPE html>
<html>
<head><title>UDS Diagnostic Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{ font-family: Arial; margin: 20px; }}
  .pass {{ color: green; font-weight: bold; }}
  .fail {{ color: red; font-weight: bold; }}
  .wrapper {{
    display: flex;
    justify-content: center;
    align-items: flex-start;
    gap: 50px;
    margin-top: 20px;
  }}
  .summary-block {{ text-align: left; min-width: 250px; }}
  #chart-container {{ width: 300px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
  th, td {{ border: 1px solid #ccc; padding: 8px; }}
  th {{ background: #f0f0f0; }}
  summary {{ font-weight: bold; cursor: pointer; }}
</style>
</head>
<body>

<h1 style="text-align: center;">UDS Diagnostic Report</h1>

<div style="display: flex; justify-content: flex-start; align-items: flex-start; gap: 40px; margin-top: 20px; padding-left: 10px;">
    <div style="width: 650px;">
        {f"<p><strong>Target ECU:</strong> {escape(target_ecu)}</p>" if target_ecu else ""}
        {"".join(f"<p><strong>{escape(k)}:</strong> {escape(v)}</p>" for k, v in (ecu_info_data or {}).items())}
        <hr style="width: 300px;border:1px solid #999; margin:25px 0;">
        <p><strong>Generated:</strong> {generated_time}</p>
        <p><strong>CAN Log File:</strong> {asc_filename}</p>
        <p><strong>Total Test Cases:</strong> {total}</p>
        <p class="pass"><strong>Passed:</strong> {passed}</p>
        <p class="fail"><strong>Failed:</strong> {failed}</p>
        <p><strong>Start_Time:</strong> {Start_Timestamp}</p>
        <p><strong>End_Time:</strong> {End_Timestamp}</p>
        <p><strong>Test Duration:</strong> {duration:.3f} seconds</p>
    </div>
    <button onclick="document.querySelectorAll('.case-block').forEach(el => el.style.display='');">Show All</button>
    <div id="chart-container" style="width: 320px; margin-left:70px;">
        <canvas id="passFailChart" width="300" height="300"></canvas>
    </div>
</div>

<script>
    const ctx = document.getElementById('passFailChart').getContext('2d');
    const chart = new Chart(ctx, {{
        type: 'pie',
        data: {{
            labels: ['Passed', 'Failed'],
            datasets: [{{
                data: [{passed}, {failed}],
                backgroundColor: ['#4CAF50', '#F44336']
            }}]
        }},
        options: {{
            responsive: true,
            onClick: function (evt, item) {{
                const segment = chart.getElementsAtEventForMode(evt, 'nearest', {{ intersect: true }}, true);
                if (!segment.length) return;
                const label = chart.data.labels[segment[0].index];
                document.querySelectorAll('.case-block').forEach(el => el.style.display = 'none');
                if (label === 'Passed') {{
                    document.querySelectorAll('.pass-case').forEach(el => el.style.display = '');
                }} else if (label === 'Failed') {{
                    document.querySelectorAll('.fail-case').forEach(el => el.style.display = '');
                }}
            }},
            plugins: {{
                legend: {{ position: 'bottom' }},
                title: {{ display: true, text: 'Test Case Results' }}
            }}
        }}
    }});
</script>

<hr><br>
"""

    for tc_id, steps in messages_by_tc.items():
        status = steps[0]['status']
        status_class = 'pass' if status == 'Pass' else 'fail' if status == 'Fail' else 'pending'
        html += f"<div class='case-block {status_class}-case'>\n"
        html += f"<details><summary>{escape(tc_id)} - <span class='{status_class}'>{escape(status)}</span></summary>\n"
        html += """<table><tr><th>Step</th><th>Description</th><th>Timestamp</th><th>Type</th><th>Data</th><th>Status</th><th>Failure Reason</th></tr>\n"""

        step_count = 1
        for msg in steps:
            desc = msg['desc']
            combined_desc = ""

            if "PreCondition:" in desc and "Testcase" in desc:
                parts = desc.split("PreCondition:", 1)[1].split("Testcase", 1)
                pre_detail = parts[0].strip()
                tc_detail = parts[1].strip()
                combined_desc = f"<b>PreCondition:</b> {escape(pre_detail)}<br><b>Testcase:</b>{escape(tc_detail)}"
            elif "PreCondition:" in desc:
                pre_detail = desc.split("PreCondition:", 1)[1].strip()
                combined_desc = f"<b>PreCondition:</b> {escape(pre_detail)}"
            else:
                combined_desc = escape(desc.strip())

            req_data = get_valid_request_data(msg.get('data_bytes', []))
            req_data_str = ' '.join(flatten_bytes(req_data))

            Expected_resp = msg.get('expected_resp', [])
            Expected_resp_str = ' '.join(flatten_bytes(Expected_resp))

            html += f"<tr><td>{step_count}</td><td>{combined_desc}</td><td>{msg['timestamp']:.6f}</td><td>Request Sent</td><td>{escape(req_data_str)}</td><td></td><td>-</td></tr>\n"
            step_count += 1
            html += f"<tr><td>{step_count}</td><td></td><td></td><td>Expected_data</td><td>{escape(Expected_resp_str)}</td><td></td><td>-</td></tr>\n"
            step_count += 1

            response = msg.get("response", {})
            raw_resp = msg.get("response_data_bytes", response.get("data_bytes", []))
            # Remove padding (AA) from response tail
            clean_resp = remove_trailing_padding(raw_resp, "AA")
            format_type = msg.get("format", "Hex").strip().lower()
            try:
                full_hex_str = ' '.join(clean_resp)
                payload = clean_resp

                # If it's a 0x62 positive RDBI, drop SID+DID from the "value" view
                if "62" in [b.upper() for b in clean_resp]:
                    idx = next(i for i, b in enumerate(clean_resp) if b.upper() == "62")
                    if len(clean_resp) > idx + 2:
                        payload = clean_resp[idx + 3:]
                    else:
                        payload = []
                else:
                    payload = clean_resp

                if format_type == "ascii":
                    ascii_str = ''.join(chr(int(b, 16)) for b in payload if 32 <= int(b, 16) <= 126)
                    response_data_str = f"{full_hex_str} -> {ascii_str}" if ascii_str else full_hex_str
                elif format_type == "decimal":
                    decimal_str = ' '.join(str(int(b, 16)) for b in payload)
                    response_data_str = f"{full_hex_str} -> {decimal_str}" if decimal_str else full_hex_str
                else:
                    response_data_str = full_hex_str
            except Exception:
                response_data_str = ' '.join(clean_resp)

            html += (
                f"<tr><td>{step_count}</td><td></td>"
                f"<td>{response.get('timestamp', 0):.6f}</td>"
                f"<td>Response Received</td>"
                f"<td>{escape(response_data_str)}</td>"
                f"<td>{escape(msg['status'])}</td>"
                f"<td>{escape(msg.get('failure_reason', ''))}</td></tr>\n"
            )
            step_count += 1

        html += "</table></details></div>\n"

    html += "</body></html>"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ UDS HTML Report generated at:\n{output_path}\n")


def generate_report(asc_file_path, txt_file_path, output_html_file, allowed_tx_ids, allowed_rx_ids, ecu_info_data=None, target_ecu=None, testcase_results=None, **kwargs):
    global DESCRIPTION_MAP
    DESCRIPTION_MAP = load_description_map(txt_file_path)
    get_description.used_tc_ids = set()

    messages_by_tc, start_ts, end_ts, base_datetime = parse_asc_file(
        asc_file_path, allowed_tx_ids, allowed_rx_ids
    )

    report_path = output_html_file

    generate_html_report(
        messages_by_tc,
        report_path,
        os.path.basename(asc_file_path),
        start_ts,
        end_ts,
        ecu_info_data,
        target_ecu,
        base_datetime
    )
