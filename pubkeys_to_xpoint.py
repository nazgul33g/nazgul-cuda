import sys

def compress_pubkey(uncompressed_hex):
    if uncompressed_hex.startswith('04'):
        uncompressed_hex = uncompressed_hex[2:]
    x = uncompressed_hex[:64]
    y = uncompressed_hex[64:128]
    if len(x) != 64 or len(y) != 64:
        raise ValueError("Invalid uncompressed pubkey length")
    prefix = '02' if int(y, 16) % 2 == 0 else '03'
    return prefix + x

def pubkeys_to_xpoint(filein, fileout):
    with open(filein) as inf, open(fileout, 'wb') as outf:
        count = 0
        skip = 0
        for line in inf:
            pubkey = line.strip().lower()

            if pubkey.startswith('04') and len(pubkey) in (130, 132):
                try:
                    pubkey = compress_pubkey(pubkey)
                except Exception as e:
                    print("skipped (compression failed):", pubkey)
                    skip += 1
                    continue

            if pubkey.startswith(('02', '03')) and len(pubkey) == 66:
                x = pubkey[2:]
            else:
                print("skipped (unsupported format):", pubkey)
                skip += 1
                continue

            try:
                outf.write(bytes.fromhex(x))
                count += 1
            except Exception as e:
                print("skipped (invalid hex):", pubkey)
                skip += 1

        print(f"✅ Processed: {count} pubkeys\n⛔ Skipped : {skip} pubkeys")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage:\n\tpython3 {sys.argv[0]} pubkeys_in.txt xpoints_out.bin")
    else:
        pubkeys_to_xpoint(sys.argv[1], sys.argv[2])
