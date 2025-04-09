import os
import json
import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
import sqlite3
import platform
from icecream import ic

YANDEX_SIGNATURE = b'\x08\x01\x12\x20'


class InvalidYandexSignature(Exception):
    pass


class InvalidMasterPasswordTypeError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"InvalidMasterPasswordTypeError: {self.message}"


def decrypt_aes_gcm256(encrypted_data, key, iv, additional_data=None):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        if additional_data:
            cipher.update(additional_data)
        return cipher.decrypt_and_verify(encrypted_data[:-16], encrypted_data[-16:])
    except Exception as e:
        raise ValueError(f"Failed to decrypt AES-GCM: {e}")


def decrypt_dpapi(ciphertext):
    # Windows DPAPI decryption using CryptUnprotectData (via ctypes)
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB(len(ciphertext),
                        ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    ):
        raise ValueError("CryptUnprotectData failed")

    data = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    kernel32.LocalFree(out_blob.pbData)
    return data


def get_sealed_key(db):
    cursor = db.cursor()
    cursor.execute("SELECT sealed_key FROM active_keys")
    row = cursor.fetchone()
    if not row:
        return None

    sealed_key_json = row[0]
    sealed_key_obj = json.loads(sealed_key_json)

    return {
        "encrypted_encryption_key": base64.b64decode(sealed_key_obj["encrypted_encryption_key"]),
        "encrypted_private_key": base64.b64decode(sealed_key_obj["encrypted_private_key"]),
        "unlock_key_salt": base64.b64decode(sealed_key_obj["unlock_key_salt"]),
        "encryption_key_algorithm": sealed_key_obj["encryption_key_algorithm"],
        "encryption_key_encryption_algorithm": sealed_key_obj["encryption_key_encryption_algorithm"],
        "key_id": sealed_key_obj["key_id"],
        "private_key_encryption_algorithm": sealed_key_obj["private_key_encryption_algorithm"],
        "unlock_key_derivation_algorithm": sealed_key_obj["unlock_key_derivation_algorithm"],
        "unlock_key_iterations": sealed_key_obj["unlock_key_iterations"],
    }


def decrypt_rsa_oaep(password, salt, iterations, encrypted_private_key, encrypted_encryption_key):
    derived_key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations, hmac_hash_module=hashlib.sha256)
    decrypted_private_key = decrypt_aes_gcm256(
        encrypted_private_key[12:], derived_key, encrypted_private_key[:12], salt
    )
    if len(decrypted_private_key) < 5:
        raise ValueError("Invalid RSA OAEP key")

    decrypted_private_key = decrypted_private_key[5:]

    private_key = RSA.importKey(decrypted_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    decrypted = cipher_rsa.decrypt(encrypted_encryption_key)

    if not decrypted.startswith(YANDEX_SIGNATURE):
        raise InvalidYandexSignature

    return decrypted[len(YANDEX_SIGNATURE):]


def get_local_encryptor_data(db, key):
    cursor = db.cursor()
    cursor.execute("SELECT value FROM meta WHERE key='local_encryptor_data'")
    row = cursor.fetchone()

    if not row:
        return None

    blob = row[0]

    ind = blob.find(b'v10')

    if ind == -1:
        raise ValueError("Couldn't find encrypted key from local_encryptor_data")

    encrypted_data = blob[ind + 3:ind + 99]

    iv = encrypted_data[:12]

    decrypted_data = decrypt_aes_gcm256(encrypted_data[12:], key, iv)

    if not decrypted_data.startswith(YANDEX_SIGNATURE):
        raise InvalidYandexSignature

    return decrypted_data[len(YANDEX_SIGNATURE):len(YANDEX_SIGNATURE) + 32]


def print_credentials(path):
    local_state_path = os.path.join(path, "Local State")

    if not os.path.exists(local_state_path):
        print(f"Local State file not found at {local_state_path}")
        return

    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state_json = json.load(f)
    except FileNotFoundError:
        print(f"Error: Local State file not found at {local_state_path}")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {local_state_path}")
        return

    encrypted_key_b64 = local_state_json["os_crypt"]["encrypted_key"]

    encrypted_dpapi_blob = base64.b64decode(encrypted_key_b64)[5:]  # Skip DPAPI prefix

    if platform.system() == 'Windows':
        master_decryptor_dpapi = decrypt_dpapi(encrypted_dpapi_blob)
    else:
        print("DPAPI decryption is only supported on Windows.")
        return

    profiles_order = local_state_json.get("profile", {}).get("profiles_order", [])

    for profile_name in profiles_order:
        profile_path = os.path.join(path, profile_name)
        db_path = os.path.join(profile_path, "Ya Passman Data")

        if not os.path.exists(db_path):
            continue

        conn = sqlite3.connect(db_path)

        try:
            sealed_keys_info = get_sealed_key(conn)
            if sealed_keys_info:
                master_password = input('Enter master password:')
                try:
                    decrypt_key = decrypt_rsa_oaep(
                        master_password,
                        sealed_keys_info["unlock_key_salt"],
                        sealed_keys_info["unlock_key_iterations"],
                        sealed_keys_info["encrypted_private_key"],
                        sealed_keys_info["encrypted_encryption_key"]
                    )
                except InvalidMasterPasswordTypeError:
                    print("Incorrect master password")
                    continue
                # except Exception as e:
                #     print(f"Error decrypting with master password: {e}")
                #     continue
            else:
                decrypt_key = get_local_encryptor_data(conn, master_decryptor_dpapi)
                if not decrypt_key:
                    print("Failed to decrypt key to decrypt encrypted data")
                    continue

            cursor = conn.cursor()
            cursor.execute(
                "SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins")

            for row in cursor.fetchall():
                origin_url, username_element, username_value, password_element, password_value, signon_realm = row

                str_to_hash = origin_url + "\x00" + username_element + "\x00" + username_value + "\x00" + password_element + "\x00" + signon_realm
                hash_object = hashlib.sha1(str_to_hash.encode('utf-8'))
                hash_result = hash_object.digest()

                if sealed_keys_info:
                    hash_result += sealed_keys_info["key_id"].encode('utf-8')

                password_value_decoded = password_value

                if len(password_value_decoded) < 12:
                    continue

                try:
                    decrypted_password = decrypt_aes_gcm256(password_value_decoded[12:], decrypt_key,
                                                            password_value_decoded[:12], hash_result)
                    print("======================================DATA======================================")
                    print("Url:", origin_url)
                    print("Login:", username_value)
                    print("Password:", decrypted_password)
                    print("================================================================================\n")
                except Exception as e:
                    print(f"Error decrypting password: {e}")
                    continue
        finally:
            conn.close()


def new_yandex_decrypt(path):
    local_state_path = os.path.join(path, "Local State")

    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state_json = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Local State file not found at {local_state_path}")
    except json.JSONDecodeError:
        raise json.JSONDecodeError(f"Could not decode JSON from {local_state_path}", '', 0)

    encrypted_key_b64 = local_state_json["os_crypt"]["encrypted_key"]

    encrypted_dpapi_blob = base64.b64decode(encrypted_key_b64)[5:]

    if platform.system() == 'Windows':
        decrypted_key = decrypt_dpapi(encrypted_dpapi_blob)
    else:
        raise OSError("DPAPI decryption is only supported on Windows.")

    profiles = [profile_name for profile_name in local_state_json.get("profile", {}).get("profiles_order", [])]

    if not profiles:
        raise ValueError("There are no profiles")

    return {
        "path": path,
        "key": decrypted_key,
        "profiles": profiles,
    }


def main():
    if platform.system() == 'Windows':
        local_app_data_path = os.environ['LOCALAPPDATA']
    elif platform.system() == 'Darwin':
        local_app_data_path = os.path.expanduser('~/Library/Application Support')
    else:
        local_app_data_path = os.path.expanduser('~/.config')

    user_data_path = os.path.join(local_app_data_path, "Yandex/YandexBrowser/User Data")

    try:
        ya_decrypt = new_yandex_decrypt(user_data_path)
        print_credentials(ya_decrypt["path"])
    except Exception as e:
        ic(e)


if __name__ == "__main__":
    main()
