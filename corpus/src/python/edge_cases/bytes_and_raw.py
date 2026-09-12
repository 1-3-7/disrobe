raw_bytes = rb"\x00\x01\\back\nslashes"
raw_string = r"C:\Users\name\folder\file.txt"
raw_fstring = rf"\path\{raw_string!r}\end"
spec_value = 3.14159
formatted = f"pi rounded {spec_value:>{10}.{3}f} done"
multiline_bytes = b"""\
line1\n\
line2\t\
"""
print(raw_bytes, raw_string, raw_fstring, formatted, multiline_bytes)
