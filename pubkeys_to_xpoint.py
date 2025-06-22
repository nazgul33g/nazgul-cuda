import sys


def compress_pubkey(uncompressed_hex):
    """
    Compress an uncompressed public key (130 hex chars, starts with '04')
    Returns 33-byte compressed pubkey hex: '02' or '03' + x
    """
    if not uncompressed_hex.startswith('04') or len(uncompressed_hex) != 130:
        raise ValueError("Invalid uncompressed public key")

    x = uncompressed_hex[2:66]
    y = uncompressed_hex[66:]

    y_last_byte = int(y[-2:], 16)
    prefix = '02' if y_last_byte % 2 == 0 else '03'
    return prefix + x


def pubkeys_to_xpoint(filein, fileout):
    with open(filein) as inf, open(fileout, 'wb') as outf:
        count = 0
        skip = 0
        for line in inf:
            pubkey = line.strip().lower()

            if len(pubkey) == 130 and pubkey.startswith('04'):
                try:
                    pubkey = compress_pubkey(pubkey)
                except Exception as e:
                    print("skipped (compression failed):", pubkey)
                    skip += 1
                    continue

            if len(pubkey) == 66 and pubkey.startswith(('02', '03')):
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
