MODULE TLSX25519;
IMPORT SYSTEM, TLSBytes;

TYPE
  GF* = ARRAY 16 OF HUGEINT;

PROCEDURE Xor64(a, b: HUGEINT): HUGEINT;
BEGIN
  RETURN SYSTEM.VAL(HUGEINT, SYSTEM.VAL(SYSTEM.SET64, a) / SYSTEM.VAL(SYSTEM.SET64, b))
END Xor64;

PROCEDURE And64(a, b: HUGEINT): HUGEINT;
BEGIN
  RETURN SYSTEM.VAL(HUGEINT, SYSTEM.VAL(SYSTEM.SET64, a) * SYSTEM.VAL(SYSTEM.SET64, b))
END And64;

PROCEDURE CopyGF(VAR r, a: GF);
VAR i: INTEGER;
BEGIN
  i := 0; WHILE i < 16 DO r[i] := a[i]; INC(i) END
END CopyGF;

PROCEDURE Car25519(VAR o: GF);
VAR i: INTEGER; carry, mul: HUGEINT;
BEGIN
  i := 0;
  WHILE i < 16 DO
    IF i = 15 THEN mul := 38 ELSE mul := 1 END;
    carry := ASH(o[i], -16);
    o[(i+1) MOD 16] := o[(i+1) MOD 16] + mul * carry;
    o[i] := o[i] MOD 65536;
    IF o[i] < 0 THEN o[i] := o[i] + 65536 END;
    INC(i)
  END
END Car25519;

PROCEDURE Sel25519(VAR p, q: GF; b: INTEGER);
VAR i: INTEGER; c, t: HUGEINT;
BEGIN
  IF b = 0 THEN c := 0 ELSE c := -1 END;
  i := 0;
  WHILE i < 16 DO
    t := And64(c, Xor64(p[i], q[i]));
    p[i] := Xor64(p[i], t);
    q[i] := Xor64(q[i], t);
    INC(i)
  END
END Sel25519;

PROCEDURE Pack25519*(VAR o: ARRAY OF CHAR; VAR n: GF);
VAR i, j, b: INTEGER; m: GF;
BEGIN
  Car25519(n); Car25519(n); Car25519(n);
  j := 0;
  WHILE j < 2 DO
    m[0] := n[0] - 65517;
    i := 1;
    WHILE i < 15 DO
      m[i] := n[i] - 65535 - ((ASH(m[i-1], -16)) MOD 2);
      m[i-1] := m[i-1] MOD 65536;
      IF m[i-1] < 0 THEN m[i-1] := m[i-1] + 65536 END;
      INC(i)
    END;
    m[15] := n[15] - 32767 - ((ASH(m[14], -16)) MOD 2);
    b := SYSTEM.VAL(INTEGER, (ASH(m[15], -16)) MOD 2);
    m[14] := m[14] MOD 65536;
    IF m[14] < 0 THEN m[14] := m[14] + 65536 END;
    Sel25519(n, m, 1-b);
    INC(j)
  END;
  i := 0;
  WHILE i < 16 DO
    o[2*i] := CHR(n[i] MOD 256);
    o[2*i+1] := CHR((n[i] DIV 256) MOD 256);
    INC(i)
  END
END Pack25519;

PROCEDURE Unpack25519(VAR o: GF; VAR n: ARRAY OF CHAR);
VAR i: INTEGER;
BEGIN
  i := 0;
  WHILE i < 16 DO
    o[i] := ORD(n[2*i]) + ORD(n[2*i+1]) * 256;
    INC(i)
  END;
  o[15] := o[15] MOD 32768
END Unpack25519;

PROCEDURE A(VAR o, a, b: GF);
VAR i: INTEGER;
BEGIN
  i := 0; WHILE i < 16 DO o[i] := a[i] + b[i]; INC(i) END
END A;

PROCEDURE Z(VAR o, a, b: GF);
VAR i: INTEGER;
BEGIN
  i := 0; WHILE i < 16 DO o[i] := a[i] - b[i]; INC(i) END
END Z;

PROCEDURE M(VAR o, a, b: GF);
VAR i, j: INTEGER; t: ARRAY 31 OF HUGEINT;
BEGIN
  i := 0; WHILE i < 31 DO t[i] := 0; INC(i) END;
  i := 0;
  WHILE i < 16 DO
    j := 0;
    WHILE j < 16 DO
      t[i+j] := t[i+j] + a[i] * b[j];
      INC(j)
    END;
    INC(i)
  END;
  i := 0; WHILE i < 15 DO t[i] := t[i] + 38 * t[i+16]; INC(i) END;
  i := 0; WHILE i < 16 DO o[i] := t[i]; INC(i) END;
  Car25519(o); Car25519(o)
END M;

PROCEDURE S(VAR o, a: GF);
BEGIN
  M(o, a, a)
END S;

PROCEDURE Inv25519(VAR o, i: GF);
VAR c: GF; a: INTEGER;
BEGIN
  CopyGF(c, i);
  a := 253;
  WHILE a >= 0 DO
    S(c, c);
    IF (a # 2) & (a # 4) THEN M(c, c, i) END;
    DEC(a)
  END;
  CopyGF(o, c)
END Inv25519;

PROCEDURE Bit(VAR z: ARRAY OF CHAR; i: INTEGER): INTEGER;
VAR j, p, v: INTEGER;
BEGIN
  v := ORD(z[i DIV 8]); p := 1; j := 0;
  WHILE j < (i MOD 8) DO p := p * 2; INC(j) END;
  RETURN (v DIV p) MOD 2
END Bit;

PROCEDURE ScalarMult*(VAR q, n, p: ARRAY OF CHAR);
VAR
  z: ARRAY 32 OF CHAR;
  i, r: INTEGER;
  x, a, b, c, d, e, f, c121665: GF;
BEGIN
  i := 0; WHILE i < 31 DO z[i] := n[i]; INC(i) END;
  z[31] := CHR((ORD(n[31]) MOD 128) + 64);
  z[0] := CHR((ORD(z[0]) DIV 8) * 8);

  Unpack25519(x, p);
  i := 0;
  WHILE i < 16 DO
    b[i] := x[i]; d[i] := 0; a[i] := 0; c[i] := 0; c121665[i] := 0;
    INC(i)
  END;
  a[0] := 1; d[0] := 1; c121665[0] := 56129; c121665[1] := 1;

  i := 254;
  WHILE i >= 0 DO
    r := Bit(z, i);
    Sel25519(a, b, r); Sel25519(c, d, r);
    A(e, a, c); Z(a, a, c); A(c, b, d); Z(b, b, d);
    S(d, e); S(f, a); M(a, c, a); M(c, b, e);
    A(e, a, c); Z(a, a, c); S(b, a); Z(c, d, f);
    M(a, c, c121665); A(a, a, d); M(c, c, a); M(a, d, f);
    M(d, b, x); S(b, e);
    Sel25519(a, b, r); Sel25519(c, d, r);
    DEC(i)
  END;
  Inv25519(c, c); M(a, a, c); Pack25519(q, a)
END ScalarMult;

PROCEDURE ScalarMultBase*(VAR q, n: ARRAY OF CHAR);
VAR base: ARRAY 32 OF CHAR; i: INTEGER;
BEGIN
  i := 0; WHILE i < 32 DO base[i] := 0X; INC(i) END;
  base[0] := 9X;
  ScalarMult(q, n, base)
END ScalarMultBase;

END TLSX25519.
