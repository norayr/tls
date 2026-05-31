MODULE TLSTestPEMBundle;
IMPORT Out, TLSBytes, TLSPEM;

VAR
  pem: ARRAY 512 OF CHAR;
  p: LONGINT;
  der: TLSBytes.Buffer;
  ok: BOOLEAN;

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR p: LONGINT; t: ARRAY OF CHAR);
VAR i: LONGINT;
BEGIN
  i := 0;
  WHILE (i < LEN(t)) & (t[i] # 0X) DO
    s[p] := t[i]; INC(p); INC(i)
  END;
  s[p] := 0X
END Append;

PROCEDURE PrintHex(VAR b: TLSBytes.Buffer);
VAR i: LONGINT;
BEGIN
  i := 0;
  WHILE i < b.len DO Out.Hex(ORD(b.data[i]), -2); INC(i) END
END PrintHex;

PROCEDURE Check(name: ARRAY OF CHAR; ok: BOOLEAN);
BEGIN
  Out.String(name);
  IF ok THEN Out.String(" OK") ELSE Out.String(" FAIL") END;
  Out.Ln
END Check;

BEGIN
  p := 0;
  Append(pem, p, "-----BEGIN CERTIFICATE-----"); Append(pem, p, "\n");
  Append(pem, p, "MIIFaw=="); Append(pem, p, "\n");
  Append(pem, p, "-----END CERTIFICATE-----"); Append(pem, p, "\n");
  Append(pem, p, "-----BEGIN CERTIFICATE-----"); Append(pem, p, "\n");
  Append(pem, p, "TWFu"); Append(pem, p, "\n");
  Append(pem, p, "-----END CERTIFICATE-----"); Append(pem, p, "\n");

  p := 0;
  ok := TLSPEM.NextCertificateDER(pem, p, der);
  Out.String("first DER = "); PrintHex(der); Out.Ln;
  Check("  first", ok & (der.len = 4) & (ORD(der.data[0]) = 30H) & (ORD(der.data[1]) = 82H));

  ok := TLSPEM.NextCertificateDER(pem, p, der);
  Out.String("second DER = "); PrintHex(der); Out.Ln;
  Check("  second", ok & (der.len = 3) & (ORD(der.data[0]) = ORD("M")) & (ORD(der.data[1]) = ORD("a")) & (ORD(der.data[2]) = ORD("n")));

  ok := TLSPEM.NextCertificateDER(pem, p, der);
  Check("  no third", ~ok)
END TLSTestPEMBundle.
