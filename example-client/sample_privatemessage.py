import nacl.encoding
import nacl.signing
import base64
from nacl.public import PrivateKey, SealedBox

hex_key = b'e278c1106318479da40b17ea4376710e11eb16c3e2a7854b2de9287ae4ed9a08'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
verify_key = signing_key.verify_key

"""pubkey = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')

verifykey = nacl.signing.VerifyKey(pubkey_hex_str, encoder=nacl.encoding.HexEncoder)"""
target_pubkey_curve = verify_key.to_curve25519_public_key()

    #Create a sealed_box with the target public key
sealed_box = nacl.public.SealedBox(target_pubkey_curve)
encrypted = sealed_box.encrypt(bytes("hello there",encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
encrypted_str = encrypted.decode('utf-8')
print("sent encrypted data: " + encrypted_str)

private_key_curve = signing_key.to_curve25519_private_key()
unseal_box = SealedBox(private_key_curve)
message_encrypted = bytes(encrypted_str, encoding='utf-8')

message_decrypted = unseal_box.decrypt(message_encrypted, encoder=nacl.encoding.HexEncoder)
message = message_decrypted.decode('utf-8')
print(message)

"""import nacl.utils
from nacl.public import PrivateKey, SealedBox

# Generate Bob's private key, as we've done in the Box example
skbob = PrivateKey.generate()
pkbob = skbob.public_key

# Alice wishes to send a encrypted message to Bob,
# but prefers the message to be untraceable
sealed_box = SealedBox(pkbob)

# This is Alice's message
message = b"Kill all kittens"

# Encrypt the message, it will carry the ephemeral key public part
# to let Bob decrypt it
encrypted = sealed_box.encrypt(message)

unseal_box = SealedBox(skbob)
# decrypt the received message
plaintext = unseal_box.decrypt(encrypted)
print(plaintext.decode('utf-8'))"""