# Test vectors

`nip44.vectors.json` is the official NIP-44 v2 test vector file from
<https://github.com/paulmillr/nip44>, vendored unchanged so the crypto can be
verified offline.

`tests/test_nip44.py` runs every group in it: conversation keys, padding
lengths, encrypt/decrypt round trips against fixed nonces, the long-message
hashes, and all the invalid cases that must be rejected.
