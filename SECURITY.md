# Security Policy

## Reporting a Vulnerability

Please report security issues privately to the repository maintainers. Do not
open a public GitHub issue for vulnerabilities that could expose ciphertext,
keys, or allow authentication bypass.

## Threat Model

`pq-objectstore` treats the object storage backend as an **untrusted ciphertext
store**. Encryption happens in the application before bytes leave the process.

### Protected

* Object payload contents
* Data encryption keys (DEKs)
* Integrity of encrypted objects (AES-GCM authentication)

### Not necessarily protected

* Bucket names
* Object keys / paths
* Object sizes
* Access timing
* S3 account metadata
* Application logs

For example, an object key such as:

```text
/cells/acme-secret-project/memory
```

leaks information through the path even though the contents are encrypted.
Applications requiring metadata confidentiality should use opaque object
identifiers.

## Key Handling

* Private ML-KEM keys must never be stored inside encrypted objects.
* Sensitive types (`SecretKey`, `SharedSecret`, `DataEncryptionKey`) are
  zeroized on drop where supported.
* Debug representations of private material are redacted.

## Cryptography

Initial suite:

* KEM: ML-KEM-768 (FIPS 203)
* Payload: AES-256-GCM STREAM
* RNG: operating-system CSPRNG
* Hash: SHA-256 where hashing is required (via ML-KEM internals)

This crate does not replace TLS.
