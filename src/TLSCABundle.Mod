MODULE TLSCABundle;
IMPORT SYSTEM, Platform, TLSBytes;

CONST
  MaxBundle* = 1048576;
  DefaultPath* = "/etc/ssl/certs/ca-certificates.crt";

TYPE
  Bundle* = RECORD
    len*: LONGINT;
    text*: ARRAY MaxBundle OF CHAR
  END;

PROCEDURE Init*(VAR b: Bundle);
BEGIN
  b.len := 0; b.text[0] := 0X
END Init;

PROCEDURE Load*(path: ARRAY OF CHAR; VAR b: Bundle): BOOLEAN;
VAR h: Platform.FileHandle; e: Platform.ErrorCode; n, total, want: LONGINT; name: ARRAY 512 OF CHAR;
BEGIN
  Init(b);
  COPY(path, name);
  e := Platform.OldRO(name, h);
  IF e # 0 THEN RETURN FALSE END;
  total := 0;
  REPEAT
    want := MaxBundle - 1 - total;
    IF want > 8192 THEN want := 8192 END;
    IF want <= 0 THEN e := 1; n := 0
    ELSE
      e := Platform.Read(h, SYSTEM.ADR(b.text[total]), want, n)
    END;
    IF e = 0 THEN INC(total, n) END
  UNTIL (e # 0) OR (n = 0) OR (total >= MaxBundle - 1);
  e := Platform.Close(h);
  IF total >= MaxBundle - 1 THEN RETURN FALSE END;
  b.len := total; b.text[total] := 0X;
  RETURN TRUE
END Load;

PROCEDURE LoadDefault*(VAR b: Bundle): BOOLEAN;
BEGIN
  RETURN Load(DefaultPath, b)
END LoadDefault;

END TLSCABundle.
