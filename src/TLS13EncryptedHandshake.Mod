MODULE TLS13EncryptedHandshake;
IMPORT Out, TLSBytes, TLS13Records, TLS13Keys, TLS13Finished;

CONST
  EncryptedExtensions* = 8;
  Certificate* = 11;
  CertificateVerify* = 15;
  Finished* = 20;

PROCEDURE MessageTotalLen*(VAR data: TLSBytes.Buffer; pos: LONGINT; VAR total: LONGINT): BOOLEAN;
VAR bodyLen: LONGINT;
BEGIN
  total := 0;
  IF pos + 4 > data.len THEN RETURN FALSE END;
  bodyLen := TLSBytes.GetBE24(data, pos + 1);
  total := 4 + bodyLen;
  IF pos + total > data.len THEN RETURN FALSE END;
  RETURN TRUE
END MessageTotalLen;

PROCEDURE MessageType*(VAR data: TLSBytes.Buffer; pos: LONGINT): LONGINT;
BEGIN
  IF pos >= data.len THEN RETURN -1 END;
  RETURN ORD(data.data[pos])
END MessageType;

PROCEDURE AppendOneMessage*(VAR transcript, data: TLSBytes.Buffer; pos, total: LONGINT);
VAR msg: TLSBytes.Buffer;
BEGIN
  TLSBytes.Slice(data, pos, total, msg);
  TLSBytes.Append(transcript, msg)
END AppendOneMessage;

PROCEDURE DropPrefix(VAR b: TLSBytes.Buffer; n: LONGINT);
VAR i, newLen: LONGINT;
BEGIN
  IF n <= 0 THEN RETURN END;
  IF n >= b.len THEN TLSBytes.Init(b); RETURN END;
  newLen := b.len - n;
  i := 0;
  WHILE i < newLen DO
    b.data[i] := b.data[i + n]; INC(i)
  END;
  b.len := newLen
END DropPrefix;

PROCEDURE ProcessServerHandshakeBuffered*(VAR plain, partial, transcript, serverFinishedKey: TLSBytes.Buffer;
                                         VAR sawFinished, finishedOK: BOOLEAN): BOOLEAN;
VAR pos, total, typ, bodyLen: LONGINT; msg, th: TLSBytes.Buffer; parsing: BOOLEAN;
BEGIN
  sawFinished := FALSE; finishedOK := FALSE;

  (* Real TLS servers may split one handshake message across several TLS records.
     So we append decrypted plaintext to PARTIAL, parse only complete handshake
     messages, and leave incomplete bytes in PARTIAL for the next record. *)
  TLSBytes.Append(partial, plain);

  pos := 0;
  parsing := TRUE;
  WHILE parsing & (pos < partial.len) DO
    IF partial.len - pos < 4 THEN
      parsing := FALSE
    ELSE
      bodyLen := TLSBytes.GetBE24(partial, pos + 1);
      total := 4 + bodyLen;
      IF partial.len - pos < total THEN
        parsing := FALSE
      ELSE
        typ := MessageType(partial, pos);
        Out.String("  hs msg type="); Out.Int(typ, 0); Out.String(" total="); Out.Int(total, 0); Out.String(" transcript before="); Out.Int(transcript.len, 0); Out.Ln;
        TLSBytes.Slice(partial, pos, total, msg);

        IF typ = Finished THEN
          TLS13Keys.HashMessages(transcript, th);
          finishedOK := TLS13Finished.VerifyFinishedMessage(msg, serverFinishedKey, th);
          sawFinished := TRUE;
          TLSBytes.Append(transcript, msg);
          Out.String("  server Finished verified="); IF finishedOK THEN Out.String("true") ELSE Out.String("false") END; Out.String(" transcript after="); Out.Int(transcript.len, 0); Out.Ln;
          IF ~finishedOK THEN RETURN FALSE END
        ELSE
          TLSBytes.Append(transcript, msg);
          Out.String("  transcript after="); Out.Int(transcript.len, 0); Out.Ln
        END;

        INC(pos, total)
      END
    END
  END;

  IF pos > 0 THEN DropPrefix(partial, pos) END;
  RETURN TRUE
END ProcessServerHandshakeBuffered;

PROCEDURE ProcessServerHandshakePlain*(VAR plain, transcript, serverFinishedKey: TLSBytes.Buffer;
                                      VAR sawFinished, finishedOK: BOOLEAN): BOOLEAN;
VAR scratch: TLSBytes.Buffer;
BEGIN
  TLSBytes.Init(scratch);
  RETURN ProcessServerHandshakeBuffered(plain, scratch, transcript, serverFinishedKey, sawFinished, finishedOK)
END ProcessServerHandshakePlain;

PROCEDURE OpenServerHandshakeRecord*(VAR serverKey, serverIV: TLSBytes.Buffer; seq: HUGEINT;
                                    VAR record, transcript, serverFinishedKey: TLSBytes.Buffer;
                                    VAR sawFinished, finishedOK: BOOLEAN): BOOLEAN;
VAR innerType: LONGINT; plain, partial: TLSBytes.Buffer;
BEGIN
  sawFinished := FALSE; finishedOK := FALSE;
  IF ~TLS13Records.OpenRecord(serverKey, serverIV, seq, record, innerType, plain) THEN RETURN FALSE END;
  IF innerType # TLS13Records.Handshake THEN RETURN FALSE END;
  TLSBytes.Init(partial);
  RETURN ProcessServerHandshakeBuffered(plain, partial, transcript, serverFinishedKey, sawFinished, finishedOK)
END OpenServerHandshakeRecord;

PROCEDURE OpenServerHandshakeRecordBuffered*(VAR serverKey, serverIV: TLSBytes.Buffer; seq: HUGEINT;
                                            VAR record, partial, transcript, serverFinishedKey: TLSBytes.Buffer;
                                            VAR sawFinished, finishedOK: BOOLEAN): BOOLEAN;
VAR innerType: LONGINT; plain: TLSBytes.Buffer;
BEGIN
  sawFinished := FALSE; finishedOK := FALSE;
  IF ~TLS13Records.OpenRecord(serverKey, serverIV, seq, record, innerType, plain) THEN RETURN FALSE END;
  IF innerType # TLS13Records.Handshake THEN RETURN FALSE END;
  RETURN ProcessServerHandshakeBuffered(plain, partial, transcript, serverFinishedKey, sawFinished, finishedOK)
END OpenServerHandshakeRecordBuffered;

PROCEDURE BuildEmptyEncryptedExtensions*(VAR msg: TLSBytes.Buffer);
BEGIN
  TLSBytes.Init(msg);
  TLSBytes.AppendByte(msg, EncryptedExtensions);
  TLSBytes.PutBE24(msg, 2);
  TLSBytes.PutBE16(msg, 0)
END BuildEmptyEncryptedExtensions;

END TLS13EncryptedHandshake.
