import crypto
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

class keyzeds (object):
    def private_keys (self) -> dict[str, crypto.PrivateKey]:
        return self.__dict__

    def public_keys (self) -> dict[str, crypto.PublicKey]:
        return {
            attr: self.__getattribute__(attr).public_key()
            for attr in self.__dict__.keys()
            if isinstance(self.__getattribute__(attr), X25519PrivateKey)
        }

class Bob(keyzeds):
    def __init__(self):
        # generate Bob's keys
        self.IK = crypto.generate_private_key()
        self.SPK = crypto.generate_private_key()
        self.OPK = crypto.generate_private_key()
        self.EK = crypto.generate_private_key()

class Alice(keyzeds):
    def __init__(self):
        # generate Alice's keys
        self.IK = crypto.generate_private_key()
        self.SPK = crypto.generate_private_key()
        self.OPK = crypto.generate_private_key()
        self.EK = crypto.generate_private_key()

alice = Alice()
bob = Bob()

ratchets_alice = None
ratchets_bob = None

while True:
    sender = input("who's sending? [alice, bob] (exit to leave)\n")
    if sender == "exit":
        break

    message = input("write the message:\n")
    if sender == "alice":
        if ratchets_alice is None and ratchets_bob is None:
            ratchets_alice = {
                "root_ratchet": crypto.create_chat_encryption(
                    alice.private_keys(), bob.public_keys(), sender=True
                )
            }
            ratchets_bob = {
                "root_ratchet": crypto.create_chat_encryption(
                    bob.private_keys(), alice.public_keys(), sender=False
                ),
                "dh_ratchet": crypto.generate_private_key()
            }

        ratchets_sender = ratchets_alice
        ratchets_receiver = ratchets_bob
    else:
        if ratchets_alice is None and ratchets_bob is None:
            ratchets_alice = {
                "root_ratchet": crypto.create_chat_encryption(
                    alice.private_keys(), bob.public_keys(), sender=False
                ),
                "dh_ratchet": crypto.generate_private_key()
            }
            ratchets_bob = {
                "root_ratchet": crypto.create_chat_encryption(
                    bob.private_keys(), alice.public_keys(), sender=True
                )
            }

        ratchets_sender = ratchets_bob
        ratchets_receiver = ratchets_alice

    cipher, snd_pbkey = crypto.snd_msg(
        ratchets_sender, ratchets_receiver["dh_ratchet"].public_key(),
        bytes(message, encoding="utf-8")
    )
    print(f"encrypted message: {crypto.decode_b64(cipher)}")

    msg = crypto.rcv_msg(ratchets_receiver, crypto.load_public_key(snd_pbkey), cipher)
    print(f"decrypted_message: {str(msg)}")

    if sender == "alice":
        ratchets_alice = ratchets_sender
        ratchets_bob = ratchets_receiver
    else:
        ratchets_alice = ratchets_receiver
        ratchets_bob = ratchets_sender