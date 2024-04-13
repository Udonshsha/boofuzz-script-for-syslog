import zlib
import hashlib
from boofuzz import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import os
import time

# Blowfish 암호화 함수
def encrypt_blowfish(key_hex, data):
    key = binascii.unhexlify(key_hex)
    cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    block_size = 8  # Blowfish 블록 크기는 8바이트
    padding_required = (block_size - len(data) % block_size) % block_size
    padded_data = data + b'\x00' * padding_required  # 0으로 패딩

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# MD5 체크섬 계산 함수
def calculate_md5_checksum(data):
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    return md5_hash.hexdigest()

# 암호화 및 압축된 데이터 생성 함수
def create_encrypted_compressed_msg(key_hex, data):
    compressed_data = zlib.compress(data.encode())
    checksum = calculate_md5_checksum(compressed_data).encode()
    encrypted_data = encrypt_blowfish(key_hex, compressed_data)
    final_msg = checksum + encrypted_data
    return final_msg

# 다양한 시나리오를 시뮬레이션하는 퍼징 데이터 생성 함수
def fuzzable_encrypted_compressed_msgs(key_hex):
    fuzzable_msgs = []
    scenarios = [
        {"name": "valid_file.txt", "checksum": "valid_checksum"},
        {"name": "new_file.txt", "checksum": "valid_checksum"},
        {"name": "valid_file.txt", "checksum": "changed_checksum"},
        {"name": "deleted_file.txt", "checksum": "-1"},
        {"name": "new_added_file.txt", "checksum": "new_file_checksum"}
    ]

    for scenario in scenarios:
        unique_data = f"{scenario['name']}_{scenario['checksum']}_{int(time.time())}_{os.urandom(10).decode('latin1')}"
        encrypted_compressed_msg = create_encrypted_compressed_msg(key_hex, unique_data)
        fuzzable_msgs.append(bytes(encrypted_compressed_msg))
    return fuzzable_msgs

def main():
    #key_hex = keydata
    #agent_id =  userdata
    session = Session(
        target=Target(
#            connection=SocketConnection("ip", port, proto=)
        ),
    )

    s_initialize(name="secure_message")

    with s_block("message_block"):
        s_static(":")
        s_static("!")
        s_string(agent_id, fuzzable=False)
        s_static("#")
        s_static("!")
        s_static("-")

        # 메시지 생성
        s_group("encrypted_compressed_msgs", values=fuzzable_encrypted_compressed_msgs(key_hex))
        s_string("ENCRYPTED_MESSAGE", fuzzable=True)
        s_string("INVALID_SIZE_OR_VALUE", fuzzable=True)
        s_string("EXTRA_DATA", fuzzable=True)

        s_static("\n");
    session.connect(s_get("secure_message"))
    session.fuzz()

if __name__ == "__main__":
    main()

