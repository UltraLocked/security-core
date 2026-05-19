# `.ultralocked` Bundle Format

The `.ultralocked` bundle is used to export and import encrypted vault items
across devices.

## High-Level Layout

```text
[96-byte public header]
[encrypted manifest ciphertext]
[manifest AES-GCM tag]
[item record 0 ciphertext]
[item record 0 AES-GCM tag]
...
[item record n ciphertext]
[item record n AES-GCM tag]
```

The manifest records item metadata and byte lengths. Item plaintext is not
stored in the manifest.

## Header

The public header is 96 bytes:

```text
offset  size  field
0       8     magic              "ULOCKED1"
8       2     version            u16 little endian
10      1     kdf_id             1 = Argon2id
11      4     argon2_time_cost   u32 little endian
15      4     argon2_memory_kib  u32 little endian
19      1     argon2_parallelism u8
20      16    salt               random
36      12    manifest_nonce     random
48      4     manifest_size      u32 little endian
52      44    reserved           zeroed
```

The header is public, but it is authenticated. The serialized 96-byte header is
used as AES-GCM additional authenticated data for the encrypted manifest and as
part of the AAD for every item record.

## Key Derivation

The user passphrase is converted to a 32-byte master key with Argon2id.

Default parameters:

```text
time_cost: 3
memory_kib: 65536
parallelism: 4
output: 32 bytes
```

The parameters and salt are stored in the header so old bundles remain
decryptable if future defaults change.

Parser limits bound attacker-controlled KDF parameters before expensive work:

```text
time_cost: 1...10
memory_kib: 8...262144
parallelism: 1...8
manifest_size: 16 bytes...1 MiB
item_size: 16 bytes...250 MiB
total_file_size: <= 2 GiB
```

## Manifest Encryption

The manifest key is derived with HKDF-SHA256:

```text
info = "UltraLocked-Export-v1-Manifest"
output = 32 bytes
```

The manifest plaintext is deterministic JSON with:

- schema version
- export timestamp
- optional export label
- item descriptors

It is encrypted with AES-256-GCM using the manifest nonce from the header and
the full header as AAD.

## Item Encryption

Each item has a unique AES-256-GCM key derived with HKDF-SHA256:

```text
info = "UltraLocked-Export-v1-Item-" || item_uuid_raw_bytes
output = 32 bytes
```

Each item record is:

```text
ciphertext || 16-byte tag
```

Each item AAD is:

```text
header_bytes || item_uuid_raw_bytes
```

This prevents ciphertext swapping between item slots. Supplying the wrong item
id, tampering with the header, or modifying any byte of the record causes
authentication failure.

## TTL Handling

Bundles may preserve a source item's TTL:

- `ttl_seconds`
- `ttl_origin_epoch`

The fields must be both present or both absent. Importers can calculate
remaining time on the destination device rather than resetting expiration
silently.

## Failure Model

The parser should fail closed for:

- invalid magic
- unsupported version
- unsupported KDF id
- out-of-range KDF parameters
- truncated header, manifest, or item records
- undersized encrypted manifest or item records
- oversized manifest, item, or full bundle
- duplicate item ids
- inconsistent TTL fields
- wrong passphrase
- modified header, manifest, item ciphertext, item id, nonce, or tag
