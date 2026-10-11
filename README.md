# tls

TLS 1.3 (RFC 8446) written in Oberon, for the [voc](https://github.com/vishaps/voc) compiler and
for [polpo](https://github.com/polpo-system/polpo), which uses the same files (only their import
lines differ). It uses only 32 bit integers, so it runs wherever these compilers do, and the
cryptography is its own: no OpenSSL.

## What it does

- **The client:** X25519, or P-256 when the server asks for it with a HelloRetryRequest;
  TLS_AES_128_GCM_SHA256; randomness from `/dev/urandom`.
- **Checking the server:**
  - its certificate chain must lead to a root of `$SSL_CERT_FILE` or
    `/etc/ssl/certs/ca-certificates.crt`. RSA PKCS#1 and RSASSA-PSS, and ECDSA P-256, P-384 and
    P-521 signatures are understood;
  - validity, CA, key usage and name constraints are checked;
  - the certificate must be for the host name or IP address;
  - CertificateVerify and Finished must be right.

  Otherwise the connection is refused with the alert that says why. `ConnectPinned` accepts a
  server by the hash of its key instead, for protocols that trust on first use (Gemini).
- **Client certificates:** when a server asks for one, the client presents an identity
  (`TLS13Live.SetIdentity`) and signs its CertificateVerify, or sends an empty Certificate.
- **After the handshake:** KeyUpdate is followed both ways, and a connection that ends without
  close_notify is reported.
- **The server side** (`TLS13Server`): the same suite and groups, with a HelloRetryRequest when a
  client offers neither key share. The certificate is chosen by the host name the client asks for
  (SNI, `AcceptBy`), so one port can serve several hosts. There are no session tickets.
- **Identities** (`TLSIdentity`): a certificate chain and its key, ECDSA P-256 or RSA (2048 bits
  or more). They're read from PEM (`CERTIFICATE`; `EC PRIVATE KEY`, `RSA PRIVATE KEY` or
  `PRIVATE KEY`) and checked to belong together. They sign with ecdsa_secp256r1_sha256 (RFC 6979
  nonces) or rsa_pss_rsae_sha256 (CRT, each signature checked before it is sent). Servers and
  clients use them alike.
- **New certificates** (`TLSCertGen`): self-signed X.509 v3 with a new P-256 key, for an identity
  (name and mail) or a server (with its host name), written as PEM, with the key as PKCS #8. So
  openssl is not needed to make them.

The arithmetic is not constant time: the code suits experimental servers and clients rather than
places where an attacker can measure many handshakes.

## Using it

A client:

```oberon
IF TLS13Live.Connect("example.org", "443", s) THEN
  ok := TLS13Live.WriteAppString(s, request);
  WHILE TLS13Live.ReadAppMax(s, buf, LEN(buf) - 1, n) DO ... END;
  TLS13Live.Disconnect(s)
ELSE Out.String(TLS13Live.lastError)
END
```

With a client certificate: `TLSIdentity.Load(cert, key, id)`, then `TLS13Live.SetIdentity(id)`
before connecting. After a connection, `TLS13Live.certPin` is the SHA-256 of the server's
certificate and `TLS13Live.keyPin` that of its key.

A server, on a connection the caller accepted (with a timeout set on it):

```oberon
IF TLS13Server.Load("cert.pem", "key.pem", id) THEN
  ...
  IF TLS13Server.Accept(fd, id, s) THEN   (* s is then a TLS13Live.State, read and written as above *)
    ...
    TLS13Live.Disconnect(s)
  ELSE Out.String(TLS13Server.lastError)
  END
END
```

`TLS13Server.AcceptBy(fd, choose, s)` takes a procedure that gives the certificate for the host
name of the client (`TLS13Server.serverName`), or NIL to refuse it with unrecognized_name.

A new self-signed certificate: `TLSCertGen.SelfSigned(name, mail, dnsName, years, certPEM,
keyPEM)`; pass `""` for the mail or the host name you don't want.

## The modules

| modules | |
| --- | --- |
| `TLSBytes`, `BIT`, `TLSNum` | byte buffers, 32 bit words, big numbers (Montgomery) |
| `TLSSHA256`, `TLSSHA512`, `TLSHKDF` | hashes, HMAC, HKDF |
| `TLSAESGCM`, `TLSX25519`, `TLSECDSA`, `TLSRSA` | AES-128-GCM, X25519, ECDSA and ECDH (P-256/384/521), RSA |
| `TLSASN1`, `TLSBase64`, `TLSPEM` | DER, Base64, PEM (read and write) |
| `TLSX509`, `TLSX509Ext`, `TLSX509Names`, `TLSX509Validity`, `TLSNameConstraints`, `TLSX509Chain`, `TLSSig`, `TLSCABundle`, `TLSNow` | certificates and their chains |
| `TLS13Handshake`, `TLS13Keys`, `TLS13Records`, `TLS13EncHandshake`, `TLS13Certs`, `TLS13Finished`, `TLS13ClientFinished`, `TLS13Application`, `TLS13Random` | the protocol |
| `TLS13Live` | client connections |
| `TLSIdentity`, `TLSCertGen`, `TLS13Server` | identities, new certificates, the server side |
| `httpsPure` | HTTPS for the http module |

Programs: `tlsConnect host port` (connect and report), `httpsGet host port path [file]`,
`tlsServe cert key port [n]` (a test server), `tlsIdent host port path [cert key]` (a connection
with a client certificate), and `certGen name [mail] [dns]` (print a new certificate and key).

## Building and testing

```sh
make          # the dependencies (strutils, base64, Internet, http) are fetched into deps/
make tests    # the unit tests, against the files in test/certs
```

After the import of a module changes, run `make clean` first: voc keeps the import list of an old
symbol file when the interface stays the same, and the link then misses the new module.

The tests in `tools/` start real servers to test against (`testservers.py`, `keyupdate.sh`,
`hrrserver.sh`). For client certificates, `openssl s_server -verify 1 -www` shows what it got.

## In polpo

polpo keeps a copy in `src/lib/tls`, copied with `loksh vocsync.From tls/src/X.Mod ... src/lib/tls`,
which changes the import lines (`Out := out`, `Linux0` for `Linux0 := unixNet`). Its tests are in
`src/lib/tls/test` (`TLS_TEST_CERTS=src/lib/tls/test/certs loksh TLSTestChain.Run` and so on). The
Gemini clients (dcs, DCS, Pishmish) and servers (agena, cobweb) of polpo are built on it.
