import os
import json
import sqlite3
import base64
import hashlib
import rsa
import win32crypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from icecream import ic

YANDEX_SIGNATURE = b'\x08\x01\x12\x20'


class InvalidMasterPasswordError(Exception):
    pass


def get_decryption_key(path):
    """Получить ключ для расшифровки"""
    local_state_path = os.path.join(path, "Local State")
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)

    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    key = decrypt_dpapi(encrypted_key[5:])  # Удалить префикс 'DPAPI'
    return key


def decrypt_dpapi(encrypted_data):
    """Расшифровать данные с помощью DPAPI."""
    decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
    return decrypted_data


def get_profiles(path):
    local_state_path = os.path.join(path, "Local State")
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)

    profiles = [
        profile_name for profile_name in local_state['profile']['profiles_order']
    ]
    if not profiles:
        raise Exception("No profiles found")
    return profiles


def decrypt_aes_gcm_256(ciphertext, key, nonce, aad=None):
    """Расшифровать AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt(ciphertext)


def get_sealed_key(db):
    """Получить зашифрованный ключ."""
    cursor = db.cursor()
    cursor.execute("SELECT sealed_key FROM active_keys")
    result = cursor.fetchone()
    if not result:
        return None
    sealed_key_json = result[0]
    return json.loads(sealed_key_json)


def get_local_encryptor_data_key(db, key):
    """Получить ключ для локального шифратора."""
    cursor = db.cursor()
    cursor.execute("SELECT value FROM meta WHERE key = 'local_encryptor_data'")
    result = cursor.fetchone()
    if not result:
        return None

    blob = result[0]
    index = blob.find(b'v10')
    if index == -1:
        return None

    encrypted_key = blob[index + 3:]
    if len(encrypted_key) < 96:
        return None

    encrypted_key = encrypted_key[:96]
    decrypted_key = decrypt_aes_gcm_256(encrypted_key[12:], key, encrypted_key[:12])
    if not decrypted_key.startswith(YANDEX_SIGNATURE):
        return None

    decrypted_key = decrypted_key[len(YANDEX_SIGNATURE):]
    if len(decrypted_key) < 32:
        return None

    return decrypted_key[:32]


def decrypt_key_rsa_oaep(password, salt, iterations, encrypted_private_key, encrypted_encryption_key):
    """Расшифровать ключ RSA-OAEP."""
    derived_key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations)

    try:
        decrypted_private_key = decrypt_aes_gcm_256(encrypted_private_key[12:], derived_key, encrypted_private_key[:12], salt)
    except Exception:
        raise InvalidMasterPasswordError("Incorrect master password")

    if len(decrypted_private_key) < 5:
        raise Exception("Invalid RSA-OAEP key")

    decrypted_private_key = decrypted_private_key[5:]
    try:
        private_key = rsa.PrivateKey.load_pkcs1(decrypted_private_key)
    except Exception as e:
        raise Exception(f"Failed to parse private key: {e}")

    try:
        decrypted = rsa.decrypt(encrypted_encryption_key, private_key)
    except Exception as e:
        raise Exception(f"RSA decryption failed: {e}")

    if not decrypted.startswith(YANDEX_SIGNATURE):
        raise Exception("Invalid Yandex signature")

    return decrypted[len(YANDEX_SIGNATURE):]


def print_credentials(path):
    key = get_decryption_key(path)
    profiles = get_profiles(path)

    for profile_name in profiles:
        profile_path = os.path.join(path, profile_name)
        logins_path = os.path.join(profile_path, "Ya Passman Data")

        try:
            db = sqlite3.connect(logins_path)
        except sqlite3.Error:
            continue

        print(f"Found database: {logins_path}")
        sealed_key_data = get_sealed_key(db)

        decrypt_key = None
        master_password_required = False

        if sealed_key_data:
            master_password_required = True
            encrypted_private_key = base64.b64decode(sealed_key_data['encrypted_private_key'])
            encrypted_encryption_key = base64.b64decode(sealed_key_data['encrypted_encryption_key'])
            unlock_key_salt = base64.b64decode(sealed_key_data['unlock_key_salt'])
            unlock_key_iterations = sealed_key_data['unlock_key_iterations']

            if len(encrypted_private_key) < 12:
                continue

            while True:
                password = input("Enter master password: ")
                try:
                    decrypt_key = decrypt_key_rsa_oaep(
                        password,
                        unlock_key_salt,
                        unlock_key_iterations,
                        encrypted_private_key,
                        encrypted_encryption_key
                    )
                    print("Correct master password")
                    break
                except InvalidMasterPasswordError:
                    print("Incorrect master password")
                except Exception as e:
                    print(f"Error: {e}")
                    break
        else:
            decrypt_key = get_local_encryptor_data_key(db, key)
            if not decrypt_key:
                print("Failed to decrypt key to decrypt encrypted data")
                continue

        cursor = db.cursor()
        cursor.execute(
            "SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins")
        rows = cursor.fetchall()

        for row in rows:
            origin_url, username_element, username_value, password_element, password_value, signon_realm = row
            str_to_hash = f"{origin_url}\x00{username_element}\x00{username_value}\x00{password_element}\x00{signon_realm}"
            hash_result = hashlib.sha1(str_to_hash.encode('utf-8')).digest()

            if master_password_required:
                key_id = sealed_key_data['key_id']
                hash_result += key_id.encode('utf-8')

            try:
                decrypted_password = decrypt_aes_gcm_256(password_value[12:], decrypt_key, password_value[:12], hash_result)
                print("Url:", origin_url)
                print("Login:", username_value)
                print("Password:", decrypted_password)
                print("\n")
            except Exception as e:
                print(f"Decryption error: {e}")
        cursor.close()
        db.close()


if __name__ == "__main__":
    yandex_profile_path = os.path.expanduser("~") + r'\AppData\Local\Yandex\YandexBrowser\User Data'
    try:
        print_credentials(yandex_profile_path)
    except Exception as e:
        print(f"Error: {e}")
