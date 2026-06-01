MODULE TLSNow;
IMPORT time, TLSX509Validity;

PROCEDURE Current*(VAR t: TLSX509Validity.Time);
BEGIN
  time.Now(t.year, t.month, t.day, t.hour, t.minute, t.second)
END Current;

END TLSNow.
