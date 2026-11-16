#!/usr/bin/env python
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""Build or inspect a certificate bundle partition image.

Image layout (all fields little-endian):

    offset  size  field
    0x00    4     magic "ECBP"
    0x04    2     header version (1)
    0x06    2     header size (32)
    0x08    4     bundle version, monotonic, used for anti-rollback
    0x0C    4     bundle length in bytes
    0x10    12    reserved (zero)
    0x1C    4     CRC32 of header bytes 0x00..0x1B followed by the bundle
    0x20    N     bundle, unchanged esp_crt_bundle format (gen_crt_bundle.py output)
    ...           0xFF padding up to a 4 KB boundary
    ...           signature appended by `espsecure sign-data` (optional)

The padded region (header + bundle + padding) is what gets signed, followed by the
4 KB Secure Boot V2 signature sector.
"""

import argparse
import os
import struct
import sys
import zlib

MAGIC = 0x50424345  # "ECBP"
HEADER_VERSION = 1
HEADER_FMT = '<IHHII12sI'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
SECTOR_SIZE = 4096


def build_bundle(inputs: list[str], max_certs: int) -> tuple[bytes, int]:
    idf_path = os.environ.get('IDF_PATH')
    if not idf_path:
        sys.exit('IDF_PATH is not set')
    sys.path.insert(0, os.path.join(idf_path, 'components', 'mbedtls', 'esp_crt_bundle'))
    import gen_crt_bundle
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat

    DER, SPKI = Encoding.DER, PublicFormat.SubjectPublicKeyInfo

    gen_crt_bundle.quiet = True
    bundle = gen_crt_bundle.CertificateBundle()
    for path in inputs:
        if os.path.isfile(path):
            bundle.add_from_file(path)
        elif os.path.isdir(path):
            bundle.add_from_path(path)
        else:
            sys.exit(f'{path} is neither a file nor a directory')
    # The same root may come from several inputs, for example the default list and a custom certificate
    unique = {}
    for crt in bundle.certificates:
        unique.setdefault((crt.subject.public_bytes(), crt.public_key().public_bytes(DER, SPKI)), crt)
    bundle.certificates = list(unique.values())
    return bundle.create_bundle(max_certs), len(bundle.certificates)


def pack_image(bundle: bytes, bundle_version: int) -> bytes:
    head = struct.pack(HEADER_FMT[:-1], MAGIC, HEADER_VERSION, HEADER_SIZE, bundle_version, len(bundle), b'')
    crc = zlib.crc32(head + bundle) & 0xFFFFFFFF
    image = head + struct.pack('<I', crc) + bundle
    return image + b'\xff' * (-len(image) % SECTOR_SIZE)


def info(path: str) -> None:
    with open(path, 'rb') as f:
        data = f.read()
    magic, hdr_ver, hdr_size, bundle_ver, bundle_len, _, crc = struct.unpack_from(HEADER_FMT, data)
    if magic != MAGIC or hdr_ver != HEADER_VERSION or hdr_size != HEADER_SIZE:
        sys.exit(f'{path}: not a certificate bundle partition image')
    bundle = data[HEADER_SIZE : HEADER_SIZE + bundle_len]
    crc_ok = zlib.crc32(data[: HEADER_SIZE - 4] + bundle) & 0xFFFFFFFF == crc
    signed_len = HEADER_SIZE + bundle_len + (-(HEADER_SIZE + bundle_len) % SECTOR_SIZE)
    n_certs = struct.unpack_from('<I', bundle)[0] // 4 if bundle_len >= 4 else 0
    print(f'bundle version : {bundle_ver}')
    print(f'bundle length  : {bundle_len} bytes, {n_certs} certificates')
    print(f'CRC32          : {"ok" if crc_ok else "MISMATCH"}')
    print(f'signed region  : {signed_len} bytes')
    print(f'signature      : {len(data) - signed_len} bytes appended' if len(data) > signed_len else 'signature      : none')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--info', metavar='IMAGE', help='Print the header of an existing image and exit')
    parser.add_argument('--input', '-i', nargs='+', help='PEM/DER certificate files or directories')
    parser.add_argument('--bundle-version', type=lambda x: int(x, 0), help='Monotonic bundle version')
    parser.add_argument('--max-certs', type=int, default=200, help='Fail if the bundle has more certificates')
    parser.add_argument(
        '--partition-size',
        type=lambda x: int(x, 0),
        help='Fail if the image plus the signature sector cannot fit',
    )
    parser.add_argument('--output', '-o', help='Output image (unsigned; sign it with espsecure sign-data)')
    args = parser.parse_args()

    if args.info:
        info(args.info)
        return
    if not args.input or args.bundle_version is None or not args.output:
        parser.error('--input, --bundle-version and --output are required')

    bundle, n_certs = build_bundle(args.input, args.max_certs)
    image = pack_image(bundle, args.bundle_version)
    if args.partition_size is not None and len(image) + SECTOR_SIZE > args.partition_size:
        sys.exit(
            f'Image ({len(image)} bytes + {SECTOR_SIZE} bytes signature) '
            f'does not fit the partition ({args.partition_size} bytes)'
        )
    with open(args.output, 'wb') as f:
        f.write(image)
    print(
        f'Certificate bundle partition image: version {args.bundle_version}, {n_certs} certificates, '
        f'{len(bundle)} bytes bundle, {len(image)} bytes image -> {args.output}'
    )


if __name__ == '__main__':
    main()
