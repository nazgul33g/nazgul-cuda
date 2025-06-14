# Updated addresses_to_hash160.py (with Bech32 support)

import base58
import hashlib
from bech32 import bech32_decode, convertbits
import sys

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def bech32_to_hash160(address):
    hrp, data = bech32_decode(address)
    if data is None or len(data) < 1:
        raise ValueError("Invalid bech32 address")
    version = data[0]
    program = convertbits(data[1:], 5, 8, False)
    if program is None:
        raise ValueError("Invalid bech32 conversion")
    
    # Handle common witness versions
    if version == 0 and len(program) == 20:  # P2WPKH
        return bytes(program)
    elif version == 0 and len(program) == 32:  # P2WSH
        return hashlib.new('ripemd160', hashlib.sha256(bytes(program)).digest()).digest()
    elif version == 1 and len(program) == 32:  # Taproot
        # Use SHA256(pubkey) for matching against Taproot addresses
        return hashlib.new('ripemd160', hashlib.sha256(bytes(program)).digest()).digest()
    
    raise ValueError("Unsupported witness version or length")

def base58_to_hash160(address):
    decoded = base58.b58decode_check(address)
    if decoded[0] in [0x00, 0x05]:  # P2PKH or P2SH
        return decoded[1:]
    raise ValueError("Unsupported base58 prefix")

def main(input_file, output_file):
    with open(input_file, "r") as f_in, open(output_file, "wb") as f_out:
        for line in f_in:
            addr = line.strip()
            try:
                if addr.startswith("bc1"):
                    h160 = bech32_to_hash160(addr)
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
