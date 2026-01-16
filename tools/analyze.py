import subprocess
import sys

if not sys.argv[1:]:
    print("./analyze.py <kernel>")
    exit(1)

r = subprocess.Popen(['readelf', '-CWs', sys.argv[1]], stdout=subprocess.PIPE)
d = r.stdout.read().split(b'\n')[3:]

processed = []

for i in d:
    data = [i for i in i.strip().decode('utf-8').split(' ') if i != '']

    if len(data) == 0:
        continue

    if data[2].startswith('0x'):
        data[2] = int(data[2], base=16)
    else:
        data[2] = int(data[2], base=10)

    if len(data) > 7:
        data[7] = ' '.join(data[7:])
        data = data[:8]

    processed.append(data[1:])

processed = sorted(processed, key=lambda x: x[1], reverse=True)

for i in processed:
    address, size, type, binding, visibility, index = i[:6]

    symbol = i[6] if len(i) == 7 else "<unknown>"

    print(f"{address} {size:<8} {type} {binding} {visibility} {symbol}")