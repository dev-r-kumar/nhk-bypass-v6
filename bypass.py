from mitmproxy import http
from data.proto.Login_pb2 import LoginReq
from data.proto.uid_pb2 import Uid
from google.protobuf.message import Message
import json
import binascii
from Crypto.Cipher import AES
import base64
from mitmproxy.tools.dump import DumpMaster as mitmdump
from mitmproxy.options import Options
import os
import asyncio


MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

class Utils:
    def __init__(self):
        pass

    def checkUid(uid: str) -> bool:
        try:
            with open("uids.json", 'r') as json_file:
                data = json.load(json_file)

            if uid in data:
                return True
            return False
        
        except:
            return False


    def decode_protobuf(content: str, message: Message):
        msg = message()
        msg.ParseFromString(binascii.unhexlify(content))
        return msg
    

    def pad(text: bytes) -> bytes:
        padding_length = AES.block_size - (len(text) % AES.block_size)
        return text + bytes([padding_length] * padding_length)
    
    
    def unpad(text: bytes) -> bytes:
        padding_length = text[-1]
        if padding_length < 1 or padding_length > AES.block_size:
            raise ValueError("Invalid padding")
        return text[:-padding_length]
    

    def aes_cbc_decrypt(enc_data: str, main_key: str, main_iv: str):
        aes = AES.new(main_key, AES.MODE_CBC, main_iv)
        return Utils.unpad(aes.decrypt(binascii.unhexlify(enc_data)))
    

    def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.encrypt(Utils.pad(binascii.unhexlify(plaintext)))
    

    def hexToOctetBytes(hex_input):
        """
        Converts a hex string or bytes into bytes (octet stream).
        """
        if isinstance(hex_input, bytes):
            hex_input = hex_input.decode('utf-8')

        hex_str = ''.join(c for c in hex_input if c in '0123456789abcdefABCDEF')

        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str

        return bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2))
    

    def base64url_decode(data):
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)
    

    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")
    

class MajorLoginIntercept:

    def __init__(self):
        print("Emulator Bypass Proxy Server Is Now Online !")

    def request(self, flow: http.HTTPFlow):
        global new_md5_signature, new_jwt_token
        if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:

            # modify the device payload
            enc_body = flow.request.content
            dec_body = Utils.aes_cbc_decrypt(binascii.hexlify(enc_body), MAIN_KEY, MAIN_IV)
            final_content = Utils.decode_protobuf(binascii.hexlify(dec_body), LoginReq)

            # google login signature
            if final_content.reserved19 == "8":
                final_content.deviceData = "KqsHTxGWhpVGjd4Kv+g1TBLjFZH2bRRpS9tvXLmKPKIubL30rLJGdMg7BOhVeSopGI+ijpcS1IYA+vklEGWHWPHU84TCBM6G8x3BPkRJRo55gG04"
                final_content.reserved20 = b"\u0045\u0055\u0047\u0046\u0052\u0058\u0058\u0051\u0063"
            # guest login signature
            else:
                final_content.deviceData = "KqsHT0868fUX5oyeIemNym13yba2iA9ewT2eHj0rZ0udWv0PTc4449t+lP1xVdpf2MoJm44hVoUN535OY+QJMABDMeUwt/IForruS/4dZBGhvSDs"
                final_content.reserved20 = b"\u0044\u0001\u0046\u0010\u0057\u005C\u0058\u0000\u0037"


            binary_data = final_content.SerializeToString()

            final_enc_content = Utils.aes_cbc_encrypt(MAIN_KEY, MAIN_IV, Utils.hexToOctetBytes(binascii.hexlify(binary_data)).hex())

            flow.request.content = bytes.fromhex(final_enc_content.hex())



    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
            body = flow.response.content

            final_content = Utils.decode_protobuf(binascii.hexlify(body), Uid)



async def run_proxy():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    host = os.environ.get("HOST", "0.0.0.0")
    port = os.environ.get("PORT", "8000")
    print(f"server is running at port: {host}:{port}")
    options = Options(listen_host="0.0.0.0", listen_port=int(port))
    m = mitmdump(options, loop=loop)

    addons = [
        MajorLoginIntercept()
    ]

    try:
        await m.run()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    asyncio.run(run_proxy())

