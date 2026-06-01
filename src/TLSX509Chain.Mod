MODULE TLSX509Chain;
IMPORT TLSBytes, TLSPEM, TLSX509, TLSX509Validity, TLSX509Trust, TLSRSAVerify;

CONST
  MaxDepth* = 8;

TYPE
  Result* = RECORD
    leafParsed*, allTimesOK*, allNamesOK*, allSignaturesOK*: BOOLEAN;
    rootFound*, rootTrusted*, trusted*: BOOLEAN;
    depth*: LONGINT;
    failedAt*: LONGINT;
    rootDer*: TLSBytes.Buffer
  END;

PROCEDURE Reset(VAR r: Result);
BEGIN
  r.leafParsed := FALSE; r.allTimesOK := TRUE; r.allNamesOK := TRUE;
  r.allSignaturesOK := TRUE; r.rootFound := FALSE; r.rootTrusted := FALSE;
  r.trusted := FALSE; r.depth := 0; r.failedAt := -1; TLSBytes.Init(r.rootDer)
END Reset;

PROCEDURE SameName(VAR a, b: TLSBytes.Buffer): BOOLEAN;
BEGIN
  RETURN TLSBytes.EqualConstTime(a, b)
END SameName;

PROCEDURE FindIssuerInProvidedCerts(VAR cur: TLSX509.CertInfo; VAR certs: ARRAY OF TLSBytes.Buffer; certCount: LONGINT; start: LONGINT; VAR issuerDER: TLSBytes.Buffer; VAR issuerInfo: TLSX509.CertInfo): BOOLEAN;
VAR i: LONGINT; ok, found: BOOLEAN;
BEGIN
  found := FALSE; i := start; TLSBytes.Init(issuerDER);
  WHILE (~found) & (i < certCount) & (i < LEN(certs)) DO
    ok := TLSX509.ParseCertificate(certs[i], issuerInfo);
    IF ok THEN
      IF SameName(cur.issuer, issuerInfo.subject) THEN
        TLSBytes.Copy(certs[i], issuerDER); found := TRUE
      END
    END;
    INC(i)
  END;
  RETURN found
END FindIssuerInProvidedCerts;

PROCEDURE FindIssuerInTrustAnchors(VAR cur: TLSX509.CertInfo; VAR roots: ARRAY OF TLSBytes.Buffer; rootCount: LONGINT; VAR rootDER: TLSBytes.Buffer; VAR rootInfo: TLSX509.CertInfo): BOOLEAN;
VAR i: LONGINT; ok, found: BOOLEAN;
BEGIN
  found := FALSE; i := 0; TLSBytes.Init(rootDER);
  WHILE (~found) & (i < rootCount) & (i < LEN(roots)) DO
    ok := TLSX509.ParseCertificate(roots[i], rootInfo);
    IF ok THEN
      IF SameName(cur.issuer, rootInfo.subject) THEN
        TLSBytes.Copy(roots[i], rootDER); found := TRUE
      END
    END;
    INC(i)
  END;
  RETURN found
END FindIssuerInTrustAnchors;

PROCEDURE FindIssuerInPEMBundle(VAR cur: TLSX509.CertInfo; bundle: ARRAY OF CHAR; VAR rootDER: TLSBytes.Buffer; VAR rootInfo: TLSX509.CertInfo): BOOLEAN;
VAR from: LONGINT; der: TLSBytes.Buffer; ok, found: BOOLEAN;
BEGIN
  from := 0; found := FALSE; TLSBytes.Init(rootDER);
  WHILE (~found) & TLSPEM.NextCertificateDER(bundle, from, der) DO
    ok := TLSX509.ParseCertificate(der, rootInfo);
    IF ok THEN
      IF SameName(cur.issuer, rootInfo.subject) THEN
        TLSBytes.Copy(der, rootDER); found := TRUE
      END
    END
  END;
  RETURN found
END FindIssuerInPEMBundle;

PROCEDURE StepOK(VAR childDER, issuerDER: TLSBytes.Buffer; VAR child, issuer: TLSX509.CertInfo; VAR now: TLSX509Validity.Time): BOOLEAN;
VAR ok: BOOLEAN;
BEGIN
  ok := TRUE;
  IF ~SameName(child.issuer, issuer.subject) THEN ok := FALSE END;
  IF ok THEN IF ~TLSX509Validity.ValidAt(issuer, now) THEN ok := FALSE END END;
  IF ok THEN ok := TLSRSAVerify.VerifyCertificateSignatureSHA256RSA(childDER, issuerDER) END;
  RETURN ok
END StepOK;

PROCEDURE CheckChainWithTrustAnchors*(VAR certs: ARRAY OF TLSBytes.Buffer; certCount: LONGINT; VAR roots: ARRAY OF TLSBytes.Buffer; rootCount: LONGINT; VAR now: TLSX509Validity.Time; VAR r: Result): BOOLEAN;
VAR
  curDER, issuerDER: TLSBytes.Buffer;
  cur, issuer: TLSX509.CertInfo;
  depth: LONGINT;
  found, ok, done: BOOLEAN;
BEGIN
  Reset(r);
  IF (certCount <= 0) OR (LEN(certs) <= 0) THEN RETURN FALSE END;
  TLSBytes.Copy(certs[0], curDER);
  r.leafParsed := TLSX509.ParseCertificate(curDER, cur);
  IF ~r.leafParsed THEN r.failedAt := 0; RETURN FALSE END;
  IF ~TLSX509Validity.ValidAt(cur, now) THEN r.allTimesOK := FALSE; r.failedAt := 0; RETURN FALSE END;

  depth := 0; done := FALSE; ok := TRUE;
  WHILE ok & ~done & (depth < MaxDepth) DO
    INC(depth); r.depth := depth;

    (* First try intermediates supplied by the server. *)
    found := FindIssuerInProvidedCerts(cur, certs, certCount, 1, issuerDER, issuer);
    IF found THEN
      IF ~StepOK(curDER, issuerDER, cur, issuer, now) THEN
        ok := FALSE; r.failedAt := depth; r.allNamesOK := SameName(cur.issuer, issuer.subject);
        r.allTimesOK := TLSX509Validity.ValidAt(issuer, now);
        r.allSignaturesOK := FALSE
      ELSE
        TLSBytes.Copy(issuerDER, curDER); cur := issuer
      END
    ELSE
      (* Then try trusted roots. *)
      found := FindIssuerInTrustAnchors(cur, roots, rootCount, issuerDER, issuer);
      IF found THEN
        r.rootFound := TRUE; TLSBytes.Copy(issuerDER, r.rootDer);
        IF ~StepOK(curDER, issuerDER, cur, issuer, now) THEN
          ok := FALSE; r.failedAt := depth; r.allNamesOK := SameName(cur.issuer, issuer.subject);
          r.allTimesOK := TLSX509Validity.ValidAt(issuer, now);
          r.allSignaturesOK := FALSE
        ELSE
          r.rootTrusted := TRUE; done := TRUE
        END
      ELSE
        ok := FALSE; r.failedAt := depth; r.rootFound := FALSE
      END
    END
  END;
  IF depth >= MaxDepth THEN ok := FALSE END;
  r.trusted := ok & done & r.rootTrusted & r.allTimesOK & r.allNamesOK & r.allSignaturesOK;
  RETURN r.trusted
END CheckChainWithTrustAnchors;

PROCEDURE CheckChainWithPEMBundle*(VAR certs: ARRAY OF TLSBytes.Buffer; certCount: LONGINT; bundle: ARRAY OF CHAR; VAR now: TLSX509Validity.Time; VAR r: Result): BOOLEAN;
VAR
  curDER, issuerDER: TLSBytes.Buffer;
  cur, issuer: TLSX509.CertInfo;
  depth: LONGINT;
  found, ok, done: BOOLEAN;
BEGIN
  Reset(r);
  IF (certCount <= 0) OR (LEN(certs) <= 0) THEN RETURN FALSE END;
  TLSBytes.Copy(certs[0], curDER);
  r.leafParsed := TLSX509.ParseCertificate(curDER, cur);
  IF ~r.leafParsed THEN r.failedAt := 0; RETURN FALSE END;
  IF ~TLSX509Validity.ValidAt(cur, now) THEN r.allTimesOK := FALSE; r.failedAt := 0; RETURN FALSE END;

  depth := 0; done := FALSE; ok := TRUE;
  WHILE ok & ~done & (depth < MaxDepth) DO
    INC(depth); r.depth := depth;
    found := FindIssuerInProvidedCerts(cur, certs, certCount, 1, issuerDER, issuer);
    IF found THEN
      IF ~StepOK(curDER, issuerDER, cur, issuer, now) THEN
        ok := FALSE; r.failedAt := depth; r.allSignaturesOK := FALSE
      ELSE
        TLSBytes.Copy(issuerDER, curDER); cur := issuer
      END
    ELSE
      found := FindIssuerInPEMBundle(cur, bundle, issuerDER, issuer);
      IF found THEN
        r.rootFound := TRUE; TLSBytes.Copy(issuerDER, r.rootDer);
        IF ~StepOK(curDER, issuerDER, cur, issuer, now) THEN
          ok := FALSE; r.failedAt := depth; r.allSignaturesOK := FALSE
        ELSE
          r.rootTrusted := TRUE; done := TRUE
        END
      ELSE
        ok := FALSE; r.failedAt := depth; r.rootFound := FALSE
      END
    END
  END;
  IF depth >= MaxDepth THEN ok := FALSE END;
  r.trusted := ok & done & r.rootTrusted & r.allTimesOK & r.allNamesOK & r.allSignaturesOK;
  RETURN r.trusted
END CheckChainWithPEMBundle;

END TLSX509Chain.
