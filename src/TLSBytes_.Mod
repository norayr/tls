MODULE TLSBytes;
IMPORT BIT;

CONST
  MaxLen* = 32768;

TYPE
  Buffer* = RECORD
    len*: LONGINT;
    data*: ARRAY MaxLen OF CHAR
  END;

PROCEDURE Init*(VAR b: Buffer);
BEGIN
  b.len := 0
END Init;

PROCEDURE SetLen*(VAR b: Buffer; n: LONGINT);
BEGIN
  IF (n < 0) OR (n > MaxLen) THEN HALT(20) END;
  b.len := n
END SetLen;

PROCEDURE Byte*(x: LONGINT): CHAR;
BEGIN
  RETURN CHR(x MOD 256)
END Byte;

PROCEDURE ByteH*(x: HUGEINT): CHAR;
BEGIN
  RETURN CHR(SHORT(x MOD 256))
END ByteH;

PROCEDURE AppendChar*(VAR b: Buffer; c: CHAR);
BEGIN
  IF b.len >= MaxLen THEN HALT(21) END;
  b.data[b.len] := c; INC(b.len)
END AppendChar;

PROCEDURE AppendByte*(VAR b: Buffer; x: LONGINT);
BEGIN
  AppendChar(b, Byte(x))
END AppendByte;

PROCEDURE Append*(VAR dst: Buffer; VAR src: Buffer);
VAR i: LONGINT;
BEGIN
  IF dst.len + src.len > MaxLen THEN HALT(22) END;
  i := 0;
  WHILE i < src.len DO
    dst.data[dst.len + i] := src.data[i]; INC(i)
  END;
  dst.len := dst.len + src.len
END Append;

PROCEDURE AppendOpen*(VAR dst: Buffer; VAR src: ARRAY OF CHAR; n: LONGINT);
VAR i: LONGINT;
BEGIN
  IF dst.len + n > MaxLen THEN HALT(23) END;
  i := 0;
  WHILE i < n DO
    dst.data[dst.len + i] := src[i]; INC(i)
  END;
  dst.len := dst.len + n
END AppendOpen;

PROCEDURE AppendString*(VAR dst: Buffer; s: ARRAY OF CHAR);
VAR i: LONGINT;
BEGIN
  i := 0;
  WHILE (i < LEN(s)) & (s[i] # 0X) DO
    AppendByte(dst, ORD(s[i])); INC(i)
  END
END AppendString;

PROCEDURE Copy*(VAR src, dst: Buffer);
VAR i: LONGINT;
BEGIN
  dst.len := src.len;
  i := 0;
  WHILE i < src.len DO dst.data[i] := src.data[i]; INC(i) END
END Copy;

PROCEDURE Slice*(VAR src: Buffer; pos, n: LONGINT; VAR dst: Buffer);
VAR i: LONGINT;
BEGIN
  IF (pos < 0) OR (n < 0) OR (pos + n > src.len) OR (n > MaxLen) THEN HALT(24) END;
  dst.len := n;
  i := 0;
  WHILE i < n DO dst.data[i] := src.data[pos + i]; INC(i) END
END Slice;

PROCEDURE GetBE16*(VAR b: Buffer; pos: LONGINT): LONGINT;
BEGIN
  RETURN ORD(b.data[pos]) * 256 + ORD(b.data[pos+1])
END GetBE16;

PROCEDURE GetBE24*(VAR b: Buffer; pos: LONGINT): LONGINT;
BEGIN
  RETURN ORD(b.data[pos]) * 65536 + ORD(b.data[pos+1]) * 256 + ORD(b.data[pos+2])
END GetBE24;

PROCEDURE GetBE32*(VAR b: Buffer; pos: LONGINT): LONGINT;
VAR v: HUGEINT;
BEGIN
  v := ORD(b.data[pos]);
  v := v * 256 + ORD(b.data[pos+1]);
  v := v * 256 + ORD(b.data[pos+2]);
  v := v * 256 + ORD(b.data[pos+3]);
  IF v >= 2147483648 THEN v := v - 4294967296 END;
  RETURN SHORT(v)
END GetBE32;

PROCEDURE PutBE16*(VAR b: Buffer; x: LONGINT);
BEGIN
  AppendByte(b, x DIV 256); AppendByte(b, x)
END PutBE16;

PROCEDURE PutBE24*(VAR b: Buffer; x: LONGINT);
BEGIN
  AppendByte(b, x DIV 65536); AppendByte(b, x DIV 256); AppendByte(b, x)
END PutBE24;

PROCEDURE ToU32H*(x: LONGINT): HUGEINT;
VAR h: HUGEINT;
BEGIN
  h := x;
  IF h < 0 THEN h := h + 4294967296 END;
  RETURN h
END ToU32H;

PROCEDURE FromU32H*(h: HUGEINT): LONGINT;
BEGIN
  h := h MOD 4294967296;
  IF h >= 2147483648 THEN h := h - 4294967296 END;
  RETURN SHORT(h)
END FromU32H;

PROCEDURE PutBE32*(VAR b: Buffer; x: LONGINT);
VAR h: HUGEINT;
BEGIN
  h := ToU32H(x);
  AppendChar(b, ByteH(h DIV 16777216));
  AppendChar(b, ByteH(h DIV 65536));
  AppendChar(b, ByteH(h DIV 256));
  AppendChar(b, ByteH(h))
END PutBE32;

PROCEDURE PutBE64*(VAR b: Buffer; x: HUGEINT);
VAR p: HUGEINT;
BEGIN
  p := 72057594037927936; (* 256^7 *)
  WHILE p > 0 DO
    AppendChar(b, ByteH(x DIV p));
    x := x MOD p;
    p := p DIV 256
  END
END PutBE64;

PROCEDURE XorByte*(a, b: LONGINT): INTEGER;
BEGIN
  RETURN ORD(BIT.CXOR(Byte(a), Byte(b)))
END XorByte;

PROCEDURE Xor12*(VAR a, b, out: Buffer);
VAR i: LONGINT;
BEGIN
  IF (a.len # 12) OR (b.len # 12) THEN HALT(25) END;
  out.len := 12;
  i := 0;
  WHILE i < 12 DO out.data[i] := CHR(XorByte(ORD(a.data[i]), ORD(b.data[i]))); INC(i) END
END Xor12;

PROCEDURE SeqNum12*(seq: LONGINT; VAR out: Buffer);
VAR h: HUGEINT; i: LONGINT;
BEGIN
  out.len := 12;
  i := 0; WHILE i < 8 DO out.data[i] := 0X; INC(i) END;
  h := ToU32H(seq);
  out.data[8]  := ByteH(h DIV 16777216);
  out.data[9]  := ByteH(h DIV 65536);
  out.data[10] := ByteH(h DIV 256);
  out.data[11] := ByteH(h)
END SeqNum12;

PROCEDURE EqualConstTime*(VAR a, b: Buffer): BOOLEAN;
VAR i, acc: LONGINT;
BEGIN
  IF a.len # b.len THEN RETURN FALSE END;
  acc := 0; i := 0;
  WHILE i < a.len DO acc := acc + XorByte(ORD(a.data[i]), ORD(b.data[i])); INC(i) END;
  RETURN acc = 0
END EqualConstTime;

END TLSBytes.
