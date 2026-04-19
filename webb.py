#!/usr/bin/env python3
"""
Complete Free Fire Vault Viewer
- Accepts access_token
- Gets JWT via MajorLogin
- Fetches backpack items
- Displays with filters and search
"""

from flask import Flask, render_template_string, request, jsonify
import requests
import json
import sys
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

app = Flask(__name__)

# ==================== PROTOBUF DEFINITIONS ====================
_sym_db = _symbol_database.Default()

# MajorLoginReq protobuf
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginReq_pb2', _globals)
MajorLogin = _globals['MajorLogin']
GameSecurity = _globals['GameSecurity']

# MajorLoginRes protobuf
DESCRIPTOR2 = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"|\n\rMajorLoginRes\x12\x13\n\x0b\x61\x63\x63ount_uid\x18\x01 \x01(\x04\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c\x12\n\n\x02iv\x18\x17 \x01(\x0c\x62\x06proto3')
_globals2 = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR2, _globals2)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR2, 'MajorLoginRes_pb2', _globals2)
MajorLoginRes = _globals2['MajorLoginRes']

# ==================== AES CONSTANTS ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

GET_BACKPACK_URL = "https://client.ind.freefiremobile.com/GetBackpack"
BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BODY_BYTES = bytes.fromhex(BODY_HEX)

# ==================== MAJOR LOGIN FUNCTIONS ====================
def encrypt_aes(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt_aes_cbc(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    try:
        return unpad(cipher.decrypt(data), AES.block_size)
    except Exception:
        return None

def build_major_login(open_id: str, access_token: str, platform_type: int) -> bytes:
    major = MajorLogin()
    major.event_time = "2025-03-23 12:00:00"
    major.game_name = "free fire"
    major.platform_id = 1
    major.client_version = "1.123.1"
    major.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major.system_hardware = "Handheld"
    major.telecom_operator = "Verizon"
    major.network_type = "WIFI"
    major.screen_width = 1920
    major.screen_height = 1080
    major.screen_dpi = "280"
    major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major.memory = 3003
    major.gpu_renderer = "Adreno (TM) 640"
    major.gpu_version = "OpenGL ES 3.1 v1.46"
    major.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major.client_ip = "223.191.51.89"
    major.language = "en"
    major.open_id = open_id
    major.open_id_type = "4"
    major.device_type = "Handheld"
    major.memory_available.version = 55
    major.memory_available.hidden_value = 81
    major.access_token = access_token
    major.platform_sdk_id = 1
    major.network_operator_a = "Verizon"
    major.network_type_a = "WIFI"
    major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major.external_storage_total = 36235
    major.external_storage_available = 31335
    major.internal_storage_total = 2519
    major.internal_storage_available = 703
    major.game_disk_storage_available = 25010
    major.game_disk_storage_total = 26628
    major.external_sdcard_avail_storage = 32992
    major.external_sdcard_total_storage = 36235
    major.login_by = 3
    major.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major.reg_avatar = 1
    major.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major.channel_type = 3
    major.cpu_type = 2
    major.cpu_architecture = "64"
    major.client_version_code = "2019118695"
    major.graphics_api = "OpenGLES2"
    major.supported_astc_bitset = 16383
    major.login_open_id_type = 4
    major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    major.loading_time = 13564
    major.release_channel = "android"
    major.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major.android_engine_init_flag = 110009
    major.if_push = 1
    major.is_vpn = 1
    major.origin_platform_type = str(platform_type)
    major.primary_platform_type = str(platform_type)
    return major.SerializeToString()

def get_jwt_from_access_token(access_token: str):
    """Get JWT from access token using MajorLogin endpoint"""
    # First get open_id from Garena inspect endpoint
    inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    try:
        insp_resp = requests.get(inspect_url, timeout=10)
        if insp_resp.status_code != 200:
            return None, f"Failed to inspect token: HTTP {insp_resp.status_code}"
        insp_data = insp_resp.json()
        open_id = insp_data.get('open_id')
        if not open_id:
            return None, "open_id not found in inspect response"
    except Exception as e:
        return None, f"Inspect request failed: {str(e)}"

    # Try each platform type
    platform_types = [2, 3, 4, 6, 8]
    for pt in platform_types:
        try:
            payload = build_major_login(open_id, access_token, pt)
            encrypted_payload = encrypt_aes(payload)

            url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53"
            }
            resp = requests.post(url, data=encrypted_payload, headers=headers, verify=False, timeout=10)
            if resp.status_code == 200:
                major_res = MajorLoginRes()
                major_res.ParseFromString(resp.content)
                if major_res.token:
                    return major_res.token, None
        except Exception as e:
            continue
    
    return None, "MajorLogin failed. Account may be banned or token invalid."

# ==================== PROTOBUF PARSING FOR BACKPACK ====================
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

        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields.append({'num': field_num, 'type': 0, 'value': value, 'nested': None})
        elif wire_type == 1:
            if idx + 8 > len(data):
                raise ValueError("Truncated 64-bit")
            value = int.from_bytes(data[idx:idx+8], 'little')
            idx += 8
            fields.append({'num': field_num, 'type': 1, 'value': value, 'nested': None})
        elif wire_type == 2:
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
        elif wire_type == 5:
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

def fetch_vault(jwt_token):
    """Fetch backpack items using JWT token"""
    headers = {
        "Host": "client.ind.freefiremobile.com",
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1"
    }
    try:
        response = requests.post(GET_BACKPACK_URL, headers=headers, data=BODY_BYTES, timeout=15)
        if response.status_code != 200:
            return None, f"HTTP error {response.status_code}"
        raw = response.content
        plain = decrypt_aes_cbc(raw)
        if plain is not None:
            data = plain
        else:
            data = raw
        fields, _ = parse_one_message(data, 0)
        ids = collect_item_ids(fields)
        return ids, None
    except Exception as e:
        return None, str(e)

# ==================== LOAD ITEM DATABASE ====================
def load_item_database():
    try:
        with open("data.json", "r", encoding="utf-8") as f:
            items = json.load(f)
        item_map = {}
        for item in items:
            iid = item.get('itemID')
            if iid is not None:
                item_map[iid] = item
        return item_map
    except Exception as e:
        print(f"Failed to load data.json: {e}")
        return {}

# ==================== HTML TEMPLATE ====================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free Fire Vault Viewer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }
        h1 { text-align: center; margin-bottom: 10px; color: #ffcc00; }
        .subtitle { text-align: center; margin-bottom: 30px; color: #aaa; font-size: 0.9rem; }
        .form-container {
            background: #0f0f1a;
            padding: 20px;
            border-radius: 12px;
            max-width: 600px;
            margin: 0 auto 30px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #ffcc00;
            font-weight: bold;
        }
        input, select {
            padding: 12px;
            font-size: 1rem;
            border-radius: 8px;
            border: none;
            width: 100%;
            background: #2a2a3e;
            color: #eee;
        }
        input:focus, select:focus {
            outline: none;
            ring: 2px solid #ffcc00;
        }
        button {
            padding: 12px;
            font-size: 1rem;
            border-radius: 8px;
            border: none;
            width: 100%;
            background: #ffcc00;
            font-weight: bold;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background: #e6b800;
        }
        .filter-bar {
            background: #0f0f1a;
            padding: 15px;
            border-radius: 12px;
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: flex-end;
        }
        .filter-group {
            flex: 1;
            min-width: 150px;
        }
        .filter-group label {
            font-size: 0.8rem;
            margin-bottom: 3px;
        }
        .stats {
            background: #0f0f1a;
            padding: 15px;
            border-radius: 12px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats span {
            color: #ffcc00;
            font-weight: bold;
            font-size: 1.2rem;
        }
        .error {
            color: #ff6666;
            text-align: center;
            margin-bottom: 20px;
            padding: 15px;
            background: #2a0a0a;
            border-radius: 12px;
        }
        .category {
            margin-bottom: 40px;
            background: #0f0f1a;
            border-radius: 12px;
            padding: 20px;
        }
        .category h2 {
            border-left: 5px solid #ffcc00;
            padding-left: 15px;
            margin-bottom: 20px;
            color: #ffcc00;
        }
        .item-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
        }
        .item-card {
            background: #16213e;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            transition: transform 0.2s;
        }
        .item-card:hover {
            transform: translateY(-5px);
        }
        .item-card img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            background: #0f0f1a;
            padding: 5px;
        }
        .item-name {
            font-weight: bold;
            margin-top: 10px;
            font-size: 0.9rem;
        }
        .item-id {
            font-size: 0.7rem;
            color: #aaa;
            margin-top: 5px;
        }
        .rarity {
            font-size: 0.7rem;
            margin-top: 5px;
            color: #ffcc00;
        }
        .no-items {
            text-align: center;
            padding: 40px;
            color: #aaa;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #ffcc00;
        }
        @media (max-width: 768px) {
            .filter-bar { flex-direction: column; }
            .item-grid { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
        }
    </style>
</head>
<body>
    <h1>🎮 Free Fire Vault Viewer</h1>
    <div class="subtitle">Enter your Access Token to view your items</div>
    
    <div class="form-container">
        <form method="post">
            <div class="form-group">
                <label>🔑 Access Token</label>
                <input type="text" name="access_token" placeholder="Enter your Garena access token" required value="{{ request.form.get('access_token', '') }}">
            </div>
            <button type="submit">🔓 Show My Vault</button>
        </form>
    </div>

    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}

    {% if all_items %}
    <div class="filter-bar">
        <div class="filter-group">
            <label>🔍 Search by Name or ID</label>
            <input type="text" id="searchInput" placeholder="Type to search..." onkeyup="filterItems()">
        </div>
        <div class="filter-group">
            <label>🏷️ Filter by Type</label>
            <select id="typeFilter" onchange="filterItems()">
                <option value="all">All Types</option>
                {% for type_name in all_types %}
                <option value="{{ type_name }}">{{ type_name }}</option>
                {% endfor %}
            </select>
        </div>
        <div class="filter-group">
            <label>⭐ Filter by Rarity</label>
            <select id="rarityFilter" onchange="filterItems()">
                <option value="all">All Rarities</option>
                <option value="EPIC">EPIC</option>
                <option value="LEGENDARY">LEGENDARY</option>
                <option value="MYTHIC">MYTHIC</option>
                <option value="RARE">RARE</option>
                <option value="COMMON">COMMON</option>
            </select>
        </div>
    </div>

    <div class="stats">
        📦 Total Items: <span id="totalCount">{{ total_items }}</span>
    </div>

    <div id="itemsContainer">
        {% for type_name, items in grouped.items() %}
            <div class="category" data-type="{{ type_name }}">
                <h2>{{ type_name }} (<span class="category-count">{{ items|length }}</span>)</h2>
                <div class="item-grid">
                    {% for item in items %}
                        <div class="item-card" 
                             data-name="{{ item.name|lower }}" 
                             data-id="{{ item.id }}" 
                             data-rarity="{{ item.rare }}">
                            <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ item.id }}.png" 
                                 onerror="this.src='https://via.placeholder.com/100?text=No+Icon'">
                            <div class="item-name">{{ item.name }}</div>
                            <div class="item-id">ID: {{ item.id }}</div>
                            {% if item.rare %}
                                <div class="rarity">⭐ {{ item.rare }}</div>
                            {% endif %}
                        </div>
                    {% endfor %}
                </div>
            </div>
        {% endfor %}
    </div>
    {% endif %}

    <script>
        function filterItems() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value;
            const rarityFilter = document.getElementById('rarityFilter').value;
            
            const categories = document.querySelectorAll('.category');
            let totalVisible = 0;
            
            categories.forEach(category => {
                const categoryType = category.getAttribute('data-type');
                const items = category.querySelectorAll('.item-card');
                let categoryVisible = 0;
                
                items.forEach(item => {
                    const name = item.getAttribute('data-name');
                    const id = item.getAttribute('data-id');
                    const rarity = item.getAttribute('data-rarity');
                    
                    let matchesSearch = name.includes(searchTerm) || id.includes(searchTerm);
                    let matchesType = (typeFilter === 'all' || categoryType === typeFilter);
                    let matchesRarity = (rarityFilter === 'all' || rarity === rarityFilter);
                    
                    if (matchesSearch && matchesType && matchesRarity) {
                        item.style.display = '';
                        categoryVisible++;
                        totalVisible++;
                    } else {
                        item.style.display = 'none';
                    }
                });
                
                const grid = category.querySelector('.item-grid');
                const countSpan = category.querySelector('.category-count');
                if (countSpan) countSpan.textContent = categoryVisible;
                
                if (categoryVisible === 0) {
                    category.style.display = 'none';
                } else {
                    category.style.display = '';
                }
            });
            
            document.getElementById('totalCount').textContent = totalVisible;
        }
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTE ====================
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        access_token = request.form.get('access_token', '').strip()
        if not access_token:
            return render_template_string(HTML_TEMPLATE, error="Access token is required")
        
        # Step 1: Get JWT from access token
        jwt_token, err = get_jwt_from_access_token(access_token)
        if err:
            return render_template_string(HTML_TEMPLATE, error=err)
        
        # Step 2: Fetch vault items using JWT
        item_ids, err = fetch_vault(jwt_token)
        if err:
            return render_template_string(HTML_TEMPLATE, error=f"Failed to fetch vault: {err}")
        
        # Step 3: Load item database and map items
        item_map = load_item_database()
        
        # Step 4: Group by type
        grouped = defaultdict(list)
        for iid in item_ids:
            info = item_map.get(iid, {})
            item_type = info.get('type', 'Unknown')
            grouped[item_type].append({
                'id': iid,
                'name': info.get('name', f'Unknown ({iid})'),
                'rare': info.get('Rare', ''),
                'icon': info.get('icon', '')
            })
        
        # Sort groups and items
        grouped = dict(sorted(grouped.items()))
        for t in grouped:
            grouped[t].sort(key=lambda x: x['name'])
        
        all_types = list(grouped.keys())
        total_items = sum(len(items) for items in grouped.values())
        
        return render_template_string(HTML_TEMPLATE, 
                                    grouped=grouped, 
                                    all_types=all_types,
                                    total_items=total_items,
                                    all_items=True,
                                    error=None)
    
    return render_template_string(HTML_TEMPLATE, grouped=None, all_items=False, error=None)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    print("=" * 50)
    print("Free Fire Vault Viewer")
    print("=" * 50)
    print("Server running at: http://localhost:5000")
    print("Enter your Garena access token to view your items")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)