#!/bin/python3
import base64

decrypt_me = "dX9ydEhnWwBsfQBEbHBBSkNHA2xeBxdHAEFO"
b64_decoded = str(base64.b64decode(decrypt_me).decode("utf-8"))
for pin in range(0,10):
    print(f"Using pin {pin} : ",end="")
    decoded = []
    for char in b64_decoded:
        c = ord(char) ^ ord(str(pin))
        decoded.append(chr(c))
    print("".join(decoded))

