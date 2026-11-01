# Certificate fixture provenance

Synthetic X.509 certificates for `tests/certificates.rs`, `tests/x509_format.rs`,
the CLI tests and the browser certificate tests. They carry no third-party
names or keys. Generated on 2026-11-01 with OpenSSL 3.5.9 (29 Sep 2026) on
macOS arm64. The private keys were generated for this purpose and deleted
afterwards; they are not in the repository.

| Fixture | Size (B) | SHA-256 |
| --- | --- | --- |
| `chain-crlf.pem` | 3042 | `d474ed806edb6235b9f583627bb438fe41cb956f747dfdc21f69b079eab3fa7e` |
| `chain.pem` | 2991 | `d91e9dfb188a869bdafb5b6c6d449a3d2a856aecdfc30828d00e97ddbb27ba0c` |
| `expired.der` | 323 | `a3f6781c45cd9f4433d93abb76d2e10fb13d12f9fa848c3e0fd6eea60ac8504d` |
| `intermediate.der` | 684 | `d8aa41a1c5c0ecbe49206654b52801b5c543f6bd8ea2f400cd18024afeddcd34` |
| `leaf.der` | 527 | `6ff05cfb09f06881ca984faa9cb34dde93904204c6e83a47da93dd3fb76d7540` |
| `not-a-certificate.pem` | 115 | `efbb96e691d1eaa3fd50ec2b06d754ea9da00d83f3dc006f0129b73ba3db06a7` |
| `root.der` | 876 | `08d8d39dbbf7adc7905aa00d579d2807d45d8661e476fb645b67fa9b168c394c` |

| Fixture | Subject CN | Issuer CN | Key | Signature | Validity (UTC) |
| --- | --- | --- | --- | --- | --- |
| `root.der` | Zrax Fixture Root CA | itself | RSA 2048 | sha256WithRSAEncryption | 2025-01-01 to 2125-01-01 |
| `intermediate.der` | Zrax Fixture Intermediate CA | root | EC P-256 | sha256WithRSAEncryption | 2025-01-01 to 2075-01-01 |
| `leaf.der` | Zrax Fixture Code Signing | intermediate | Ed25519 | ecdsa-with-SHA256 | 2025-01-01 to 2050-01-01 |
| `expired.der` | Zrax Fixture Expired | itself | Ed25519 | Ed25519 | 2000-01-01 to 2001-01-01 |

The root, intermediate and leaf names also carry `C=DE` and
`O=Zrax Fixtures`. `chain.pem` holds the leaf, intermediate and root
certificates in that order with LF line ends; `chain-crlf.pem` is the same
text with CRLF line ends. `not-a-certificate.pem` is the leaf's
`SubjectPublicKeyInfo` relabelled as a `CERTIFICATE` block: valid base64
whose contents are not a certificate. Validity dates are fixed so that tests
do not depend on the current date.

`ext.cnf`:

```ini
[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectAltName = DNS:fixture.zrax.invalid, email:fixture@zrax.invalid, IP:192.0.2.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
```

Commands, in an empty temporary directory containing `ext.cnf`:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root.key
openssl req -x509 -new -key root.key -subj "/C=DE/O=Zrax Fixtures/CN=Zrax Fixture Root CA" \
  -set_serial 0x01 -not_before 20250101000000Z -not_after 21250101000000Z -sha256 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -outform DER -out root.der
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out intermediate.key
openssl req -new -key intermediate.key \
  -subj "/C=DE/O=Zrax Fixtures/CN=Zrax Fixture Intermediate CA" -out intermediate.csr
openssl x509 -req -in intermediate.csr -CA root.der -CAform DER -CAkey root.key -set_serial 0x02 \
  -not_before 20250101000000Z -not_after 20750101000000Z -sha256 \
  -extfile ext.cnf -extensions intermediate -outform DER -out intermediate.der
openssl genpkey -algorithm ED25519 -out leaf.key
openssl req -new -key leaf.key -subj "/C=DE/O=Zrax Fixtures/CN=Zrax Fixture Code Signing" -out leaf.csr
openssl x509 -req -in leaf.csr -CA intermediate.der -CAform DER -CAkey intermediate.key \
  -set_serial 0x03 -not_before 20250101000000Z -not_after 20500101000000Z -sha256 \
  -extfile ext.cnf -extensions leaf -outform DER -out leaf.der
openssl genpkey -algorithm ED25519 -out expired.key
openssl req -x509 -new -key expired.key -subj "/CN=Zrax Fixture Expired" -set_serial 0x04 \
  -not_before 20000101000000Z -not_after 20010101000000Z -outform DER -out expired.der
for c in leaf intermediate root; do openssl x509 -inform DER -in $c.der -outform PEM; done > chain.pem
perl -pe 's/\n/\r\n/' chain.pem > chain-crlf.pem
openssl pkey -in leaf.key -pubout | sed 's/PUBLIC KEY/CERTIFICATE/' > not-a-certificate.pem
rm -f *.key *.csr
```

Regenerating produces new keys, signatures and hashes; update this file and
the tests that pin hashes when doing so.
