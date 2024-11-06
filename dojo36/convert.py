payload = input("> ")
encoded = [oct(ord(c)) for c in payload]
epayload = "".join(encoded).replace('0o','\\').replace('\\40','\' $\'')
print(f"$'{epayload}'")
