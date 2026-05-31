MODULE testHttpsPure;
IMPORT httpsPure, strTypes;

PROCEDURE test;
VAR
  h: httpsPure.TLSClient;
  host: ARRAY 64 OF CHAR;
  port: ARRAY 8 OF CHAR;
  answer: strTypes.pstring;
BEGIN
  COPY("norayr.am", host); COPY("443", port);
  h := httpsPure.Create(host, port, "/");
  h.Init(h);
  answer := h.Get(h);
  h.Save(h)
END test;

BEGIN
  test
END testHttpsPure.
