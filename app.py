#!/usr/bin/env python3
"""
Fetch GetBackpack, parse, group by type, and save formatted list to vault.txt.
"""

import requests
import json
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ==================== CONFIGURATION ====================
URL = "https://client.ind.freefiremobile.com/GetBackpack"

HEADERS = {
    "Host": "client.ind.freefiremobile.com",
    "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "deflate, gzip",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjMiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMTY4NjQ3MjM1MSwibmlja25hbWUiOiIuQkEuQlUuWVQuIiwibm90aV9yZWdpb24iOiJJTkQiLCJsb2NrX3JlZ2lvbiI6IklORCIsImV4dGVybmFsX2lkIjoiYjM5NjdlMWUwYzU0N2Q1Mzk4ZDM1MzMxMWEwOGFjZWQiLCJleHRlcm5hbF90eXBlIjo4LCJwbGF0X2lkIjowLCJjbGllbnRfdmVyc2lvbiI6IjEuMTIwLjEiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjE4OTMwMDEzMzUyOTAsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzQ0MDgyODY5LCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IkRBTkdFUl9BTFdBWVNfT05fVE9QIiwicmVsZWFzZV92ZXJzaW9uIjoiT0I1MiIsImV4cCI6MTc3NDExNzI5OX0.9cKXKekCxVQ4LWio_7aQjG1a-Krj-zFhK-LpfcDADb0",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB53",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2022.3.47f1"
}

BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BODY_BYTES = bytes.fromhex(BODY_HEX)

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

DATA_JSON_PATH = "/storage/emulated/0/BACKPACK/data.json"

# ==================== DECRYPTION ====================
def decrypt_aes_cbc(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    try:
        return unpad(cipher.decrypt(data), AES.block_size)
    except Exception:
        return None

# ==================== PROTOBUF PARSING ====================
def decode_varint(data, offset):
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Truncated varint")
        b = data[offset]
        value |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return value, offset

def parse_one_message(data, start):
    fields = []
    idx = start
    while idx < len(data):
        try:
            key, idx = decode_varint(data, idx)
        except ValueError:
            break
        field_num = key >> 3
        wire_type = key & 0x07

        if wire_type == 0:          # varint
            value, idx = decode_varint(data, idx)
            fields.append({'num': field_num, 'type': 0, 'value': value, 'nested': None})
        elif wire_type == 1:        # 64-bit
            if idx + 8 > len(data):
                raise ValueError("Truncated 64-bit")
            value = int.from_bytes(data[idx:idx+8], 'little')
            idx += 8
            fields.append({'num': field_num, 'type': 1, 'value': value, 'nested': None})
        elif wire_type == 2:        # length-delimited
            length, idx = decode_varint(data, idx)
            if idx + length > len(data):
                return fields, idx
            raw = data[idx:idx+length]
            idx += length
            nested = None
            try:
                nested, _ = parse_one_message(raw, 0)
            except Exception:
                pass
            fields.append({'num': field_num, 'type': 2, 'value': raw, 'nested': nested})
        elif wire_type == 5:        # 32-bit
            if idx + 4 > len(data):
                raise ValueError("Truncated 32-bit")
            value = int.from_bytes(data[idx:idx+4], 'little')
            idx += 4
            fields.append({'num': field_num, 'type': 5, 'value': value, 'nested': None})
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
    return fields, idx

def collect_item_ids(fields):
    ids = []
    for f in fields:
        if f['num'] == 3 and f['type'] == 2 and f['nested'] is not None:
            for sub in f['nested']:
                if sub['num'] == 1 and sub['type'] == 0:
                    ids.append(sub['value'])
        if f['nested'] is not None:
            ids.extend(collect_item_ids(f['nested']))
    return ids

# ==================== LOAD ITEM DATABASE ====================
def load_item_database(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            items = json.load(f)
        item_map = {}
        for item in items:
            iid = item.get('itemID')
            if iid is not None:
                item_map[iid] = item
        print(f"Loaded {len(item_map)} items from {path}")
        return item_map
    except Exception as e:
        print(f"Failed to load item database: {e}")
        return {}

# ==================== MAIN ====================
def main():
    print("Sending GetBackpack request...")
    try:
        response = requests.post(URL, headers=HEADERS, data=BODY_BYTES, timeout=15)
    except Exception as e:
        print(f"Request failed: {e}")
        return

    print(f"Status code: {response.status_code}")
    if response.status_code != 200:
        print("Request failed.")
        return

    raw_data = response.content
    print(f"Received {len(raw_data)} bytes.")

    # Decrypt
    plain = decrypt_aes_cbc(raw_data)
    if plain is not None:
        print("AES decryption successful.")
        data = plain
    else:
        print("AES decryption failed – assuming response is already plain.")
        data = raw_data

    # Save raw hex to a separate file (optional)
    with open("vault_raw.txt", "w") as f:
        f.write(data.hex())
    print("Saved raw hex to vault_raw.txt")

    # Parse
    try:
        fields, _ = parse_one_message(data, 0)
    except Exception as e:
        print(f"Error parsing protobuf: {e}")
        return

    ids = collect_item_ids(fields)
    print(f"Found {len(ids)} item IDs.")

    # Load database
    item_map = load_item_database(DATA_JSON_PATH)

    # Group by type
    grouped = defaultdict(list)
    for item_id in ids:
        info = item_map.get(item_id, {})
        item_type = info.get('type', 'Unknown')
        grouped[item_type].append((item_id, info.get('name', 'Unknown')))

    # Build formatted output string
    output_lines = []
    output_lines.append("Items grouped by type (from data.json):\n")
    for item_type in sorted(grouped.keys()):
        items = grouped[item_type]
        output_lines.append(f"\n{item_type} ({len(items)} items):")
        for idx, (iid, name) in enumerate(items, 1):
            output_lines.append(f"    {idx:3d}. {name} (ID: {iid})")
        if len(items) > 20:
            output_lines.append(f"    ... and {len(items)-20} more items (see full list in JSON)")

    formatted_output = "\n".join(output_lines)

    # Save to vault.txt
    with open("vault.txt", "w", encoding="utf-8") as f:
        f.write(formatted_output)
    print("Saved formatted grouped list to vault.txt")

    # Also print to console
    print("\n" + formatted_output)

    # Save enriched data
    enriched = []
    for iid in ids:
        info = item_map.get(iid, {})
        enriched.append({
            "itemID": iid,
            "name": info.get('name', 'Unknown'),
            "icon": info.get('icon', ''),
            "description": info.get('description', ''),
            "Rare": info.get('Rare', ''),
            "type": info.get('type', 'Unknown')
        })
    with open("vault_enriched.json", "w") as out:
        json.dump(enriched, out, indent=2)
    print("Full enriched data saved to vault_enriched.json")

if __name__ == "__main__":
    main()