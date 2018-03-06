#!/bin/env python3

import json
import sys

from pyblake2 import blake2s

def main(output_fn):
    fd = open(output_fn, 'w')

    key_bytes = bytearray(range(32))

    fd.write('[\n')
    for i in range(8):
        salt_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2s",
                "in": "",
                "key": key_bytes.hex(),
                "persona": "",
                "salt": salt_bytes.hex(),
                "out": blake2s(key=key_bytes, salt=salt_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+',\n')

    for i in range(8):
        persona_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2s",
                "in": "",
                "key": key_bytes.hex(),
                "persona": persona_bytes.hex(),
                "salt": "",
                "out": blake2s(key=key_bytes, person=persona_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+(',' if i<7 else '')+'\n')

    fd.write(']')
    fd.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gen_vectors.py <path to output file>")
        sys.exit(1)
    main(sys.argv[1])


