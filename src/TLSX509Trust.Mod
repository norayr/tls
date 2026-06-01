MODULE TLSX509Trust;
IMPORT TLSBytes, TLSPEM, TLSX509, TLSX509Validity;

TYPE
  Result* = RECORD
    leafParsed*, issuerFound*, issuerNameOK*, issuerSelfIssued*, leafTimeOK*, issuerTimeOK*: BOOLEAN;
    signaturesOK*: BOOLEAN;
    trustedByNameAndTime*: BOOLEAN;
    issuerDer*: TLSBytes.Buffer
  END;

PROCEDURE EqualDER*(VAR a, b: TLSBytes.Buffer): BOOLEAN;
BEGIN
  RETURN TLSBytes.EqualConstTime(a, b)
END EqualDER;

PROCEDURE SubjectEqualsIssuer*(VAR subjectCert, issuerCert: TLSX509.CertInfo): BOOLEAN;
BEGIN
  RETURN EqualDER(subjectCert.issuer, issuerCert.subject)
END SubjectEqualsIssuer;

PROCEDURE IsSelfIssued*(VAR info: TLSX509.CertInfo): BOOLEAN;
BEGIN
  RETURN EqualDER(info.issuer, info.subject)
END IsSelfIssued;

PROCEDURE FindIssuerInPEMBundle*(VAR leafInfo: TLSX509.CertInfo; bundle: ARRAY OF CHAR; VAR issuerDER: TLSBytes.Buffer; VAR issuerInfo: TLSX509.CertInfo): BOOLEAN;
VAR from: LONGINT; der: TLSBytes.Buffer; ok, found: BOOLEAN;
BEGIN
  from := 0; found := FALSE; TLSBytes.Init(issuerDER);
  WHILE (~found) & TLSPEM.NextCertificateDER(bundle, from, der) DO
    ok := TLSX509.ParseCertificate(der, issuerInfo);
    IF ok THEN
      IF EqualDER(leafInfo.issuer, issuerInfo.subject) THEN
        TLSBytes.Copy(der, issuerDER);
        found := TRUE
      END
    END
  END;
  RETURN found
END FindIssuerInPEMBundle;

PROCEDURE CheckLeafWithBundleByNameAndTime*(VAR leafDER: TLSBytes.Buffer; bundle: ARRAY OF CHAR; VAR now: TLSX509Validity.Time; VAR res: Result): BOOLEAN;
VAR leaf, issuer: TLSX509.CertInfo;
BEGIN
  res.leafParsed := FALSE; res.issuerFound := FALSE; res.issuerNameOK := FALSE;
  res.issuerSelfIssued := FALSE; res.leafTimeOK := FALSE; res.issuerTimeOK := FALSE;
  res.signaturesOK := FALSE; res.trustedByNameAndTime := FALSE;
  TLSBytes.Init(res.issuerDer);

  res.leafParsed := TLSX509.ParseCertificate(leafDER, leaf);
  IF res.leafParsed THEN
    res.leafTimeOK := TLSX509Validity.ValidAt(leaf, now);
    res.issuerFound := FindIssuerInPEMBundle(leaf, bundle, res.issuerDer, issuer);
    IF res.issuerFound THEN
      res.issuerNameOK := SubjectEqualsIssuer(leaf, issuer);
      res.issuerSelfIssued := IsSelfIssued(issuer);
      res.issuerTimeOK := TLSX509Validity.ValidAt(issuer, now)
    END
  END;

  (* Signature verification is intentionally not set here yet.  This module checks
     the name chain and dates only; RSA/ECDSA signature verification comes next. *)
  res.trustedByNameAndTime := res.leafParsed & res.issuerFound & res.issuerNameOK & res.issuerSelfIssued & res.leafTimeOK & res.issuerTimeOK;
  RETURN res.trustedByNameAndTime
END CheckLeafWithBundleByNameAndTime;

END TLSX509Trust.
