import re

payload = input("Enter payload : ")

char_array = [oct(ord(c)) for c in payload]

pattern = r"[' ,\[\]]+"

result = re.sub(pattern,'',str(char_array))

print("Formated payload")
print(result.replace('0o','\\'))

