# Updated addresses_to_hash160.py (with Bech32 support)

import base58
import hashlib
import sys
import segwit_addr  # Make sure segwit_addr.py is in same folder

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def decode_bech32(address):
    """Return witness_version, witness_program, encoding"""
    hrp = 'bc'  # adjust for testnet if needed
    try:
        witver, witprog = segwit_addr.decode(hrp, address)
        if witver is None:
            raise ValueError("Invalid Bech32 checksum or format")
        return witver, bytes(witprog)
    except Exception as e:
        raise ValueError(f"Bech32 decode error: {e}")

def base58_to_hash160(address):
    decoded = base58.b58decode_check(address)
    prefix = decoded[0]
    if prefix in (0x00, 0x05):  # P2PKH, P2SH
        return decoded[1:]
    raise ValueError(f"Unsupported Base58 prefix: {prefix}")

def main(input_file, output_file):
    with open(input_file, "r") as f_in, open(output_file, "wb") as f_out:
        for line in f_in:
            addr = line.strip()
            if not addr:
                continue
            try:
                if addr.startswith("bc1"):
                    witver, prog = decode_bech32(addr)
                    if witver == 0 and len(prog) == 20:  # P2WPKH
                        h160 = prog
                    elif witver == 0 and len(prog) == 32:  # P2WSH
                        h160 = hash160(prog)
                    elif witver == 1 and len(prog) == 32:  # Taproot
                        h160 = prog  # store raw 32 bytes
                    else:
                        raise ValueError(f"Unsupported witness version {witver} or length {len(prog)}")
                else:
                    h160 = base58_to_hash160(addr)
                f_out.write(h160)
            except Exception as e:
                print(f"Skipping {addr}: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python addresses_to_hash160.py <input.txt> <output.bin>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
