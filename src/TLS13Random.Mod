MODULE TLS13Random;

IMPORT Random := ulmRandomGenerators;

(*
  Temporary PRNG-backed random filler.

  WARNING: this is not cryptographically secure.  It is useful only for
  bringing up the pure Oberon TLS client without C glue.  Later we should
  replace this module with a /dev/urandom based version or a small OS wrapper.
*)

PROCEDURE Fill*(VAR buf: ARRAY OF CHAR; n: LONGINT): BOOLEAN;
VAR i, v: LONGINT;
BEGIN
  IF (n < 0) OR (n > LEN(buf)) THEN RETURN FALSE END;
  i := 0;
  WHILE i < n DO
    v := Random.Val(0, 255);
    IF v < 0 THEN v := -v END;
    buf[i] := CHR(SHORT(v MOD 256));
    INC(i)
  END;
  RETURN TRUE
END Fill;

END TLS13Random.
