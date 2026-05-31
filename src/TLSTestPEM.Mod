MODULE TLSTestPEM;
IMPORT Out, Base64 := TLSBase64, TLSBytes, TLSPEM;

VAR
  b: TLSBytes.Buffer;
  ok, checkOK: BOOLEAN;
  pem: ARRAY 256 OF CHAR;

PROCEDURE PrintHex(VAR b: TLSBytes.Buffer);
VAR i: LONGINT;
BEGIN
  i := 0;
  WHILE i < b.len DO
    Out.Hex(ORD(b.data[i]), -2); INC(i)
  END
END PrintHex;

PROCEDURE Check(name: ARRAY OF CHAR; ok: BOOLEAN);
BEGIN
  Out.String(name);
  IF ok THEN Out.String(" OK") ELSE Out.String(" FAIL") END;
  Out.Ln
END Check;

PROCEDURE CheckMan(VAR b: TLSBytes.Buffer; VAR ok: BOOLEAN);
BEGIN
  ok := TRUE;
  IF b.len # 3 THEN ok := FALSE END;
  IF ok & (ORD(b.data[0]) # ORD("M")) THEN ok := FALSE END;
  IF ok & (ORD(b.data[1]) # ORD("a")) THEN ok := FALSE END;
  IF ok & (ORD(b.data[2]) # ORD("n")) THEN ok := FALSE END
END CheckMan;

PROCEDURE CheckMa(VAR b: TLSBytes.Buffer; VAR ok: BOOLEAN);
BEGIN
  ok := TRUE;
  IF b.len # 2 THEN ok := FALSE END;
  IF ok & (ORD(b.data[0]) # ORD("M")) THEN ok := FALSE END;
  IF ok & (ORD(b.data[1]) # ORD("a")) THEN ok := FALSE END
END CheckMa;

PROCEDURE CheckM(VAR b: TLSBytes.Buffer; VAR ok: BOOLEAN);
BEGIN
  ok := TRUE;
  IF b.len # 1 THEN ok := FALSE END;
  IF ok & (ORD(b.data[0]) # ORD("M")) THEN ok := FALSE END
END CheckM;

PROCEDURE CheckDERPrefix(VAR b: TLSBytes.Buffer; VAR ok: BOOLEAN);
BEGIN
  ok := TRUE;
  IF b.len # 4 THEN ok := FALSE END;
  IF ok & (ORD(b.data[0]) # 30H) THEN ok := FALSE END;
  IF ok & (ORD(b.data[1]) # 82H) THEN ok := FALSE END;
  IF ok & (ORD(b.data[2]) # 05H) THEN ok := FALSE END;
  IF ok & (ORD(b.data[3]) # 6BH) THEN ok := FALSE END
END CheckDERPrefix;

BEGIN
  ok := Base64.DecodeToBuffer("TWFu", b);
  CheckMan(b, checkOK);
  Out.String("b64 TWFu = "); PrintHex(b); Out.Ln;
  Check("  Man", ok & checkOK);

  ok := Base64.DecodeToBuffer("TWE=", b);
  CheckMa(b, checkOK);
  Out.String("b64 TWE= = "); PrintHex(b); Out.Ln;
  Check("  Ma", ok & checkOK);

  ok := Base64.DecodeToBuffer("TQ==", b);
  CheckM(b, checkOK);
  Out.String("b64 TQ== = "); PrintHex(b); Out.Ln;
  Check("  M", ok & checkOK);

  COPY("-----BEGIN CERTIFICATE-----", pem);
  pem[27] := 0AX; pem[28] := "M"; pem[29] := "I"; pem[30] := "I"; pem[31] := "F";
  pem[32] := "a"; pem[33] := "w"; pem[34] := "="; pem[35] := "="; pem[36] := 0AX;
  pem[37] := "-"; pem[38] := "-"; pem[39] := "-"; pem[40] := "-"; pem[41] := "-";
  pem[42] := "E"; pem[43] := "N"; pem[44] := "D"; pem[45] := " "; pem[46] := "C";
  pem[47] := "E"; pem[48] := "R"; pem[49] := "T"; pem[50] := "I"; pem[51] := "F";
  pem[52] := "I"; pem[53] := "C"; pem[54] := "A"; pem[55] := "T"; pem[56] := "E";
  pem[57] := "-"; pem[58] := "-"; pem[59] := "-"; pem[60] := "-"; pem[61] := "-";
  pem[62] := 0X;

  ok := TLSPEM.FirstCertificateDER(pem, b);
  CheckDERPrefix(b, checkOK);
  Out.String("pem DER = "); PrintHex(b); Out.Ln;
  Check("  DER prefix 3082056B", ok & checkOK)
END TLSTestPEM.
