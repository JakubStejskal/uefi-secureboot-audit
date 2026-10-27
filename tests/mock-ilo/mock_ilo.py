"""Mock iLO 6/7 Redfish endpoint for testing HPE-SecureBootAudit.ps1.

Mimics observed iLO behaviour: member links end with '/', '//' in a path -> 404,
session auth via X-Auth-Token, certificate collection members are @odata.id only.
Usage: python3 mock_ilo.py <port> <scenario>
"""
import json, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, SCEN = int(sys.argv[1]), sys.argv[2]
TOKEN = "tok-123"

HPE_PK = ("HPE UEFI Secure Boot 2016 PK Key", "2031-01-30T23:59:59Z")
KEK = [("HPE UEFI Secure Boot 2016 KEK Key", "2031-01-30T23:59:59Z"),
       ("Microsoft Corporation KEK CA 2011", "2026-06-24T20:51:29Z"),
       ("Microsoft Corporation KEK 2K CA 2023", "2038-03-02T20:31:35Z")]
DB = [("HP UEFI Secure Boot 2013 DB key", "2033-08-23T23:59:59Z"),
      ("HPE UEFI Secure Boot 2016 DB Key", "2031-01-30T23:59:59Z"),
      ("Microsoft Corporation UEFI CA 2011", "2026-06-27T21:32:45Z"),
      ("Microsoft Windows Production PCA 2011", "2026-10-19T18:51:42Z"),
      ("Microsoft UEFI CA 2023", "2038-06-13T19:31:47Z"),
      ("Microsoft Option ROM UEFI CA 2023", "2038-10-26T19:12:20Z"),
      ("Windows UEFI CA 2023", "2035-06-13T19:08:29Z"),
      ("VMware Secure Boot Signing", "2037-10-19T06:47:59Z")]
DBX = [("Canonical Ltd. Secure Boot Signing", "2042-04-11T11:39:08Z"),
       ("Virtual UEFI SubCA", "2099-04-03T16:19:30Z"),
       ("Debian Secure Boot Signer", "2026-08-16T18:22:50Z")]

model, bios, ilo = "ProLiant DL320 Gen11", "U63 v2.80 (01/29/2026)", "iLO 6"
sb_current, sb_mode = "Enabled", "UserMode"
dbs = {"PK": [HPE_PK], "KEK": KEK, "db": DB, "dbx": DBX}
no_sbdb = False
fail_cert = None

if SCEN == "gen12":
    model, bios, ilo = "HPE ProLiant Compute DL380 Gen12", "U68 v1.52 (10/03/2025)", "iLO 7"
elif SCEN == "legacy2011":   # Gen11 ROM OK, keys never reset
    dbs = {"PK": [HPE_PK], "KEK": KEK[:2], "db": DB[:4] + [DB[7]], "dbx": DBX}
elif SCEN == "sboff":        # certs fine, PK wiped -> SetupMode
    dbs = {"PK": [], "KEK": KEK, "db": DB, "dbx": DBX}
    sb_current, sb_mode = "Disabled", "SetupMode"
elif SCEN == "nodb":         # SecureBootDatabases absent
    no_sbdb = True
elif SCEN == "partial":      # one db certificate read fails
    fail_cert = ("db", 5)
elif SCEN == "oldrom":
    bios = "U63 v2.10 (01/01/2025)"
    dbs = {"PK": [HPE_PK], "KEK": KEK[:2], "db": DB[:4], "dbx": DBX}


def resources():
    r = {
        "/redfish/v1/Managers/": {"Members": [{"@odata.id": "/redfish/v1/Managers/1/"}]},
        "/redfish/v1/Managers/1/": {"Model": ilo, "FirmwareVersion": ilo + " v1.20"},
        "/redfish/v1/Systems/": {"Members": [{"@odata.id": "/redfish/v1/Systems/1/"}]},
        "/redfish/v1/Systems/1/": {"Model": model, "SerialNumber": "CZ123", "BiosVersion": bios,
                                   "ProcessorSummary": {"Model": "Intel(R) Xeon(R) 6"},
                                   "SecureBoot": {"@odata.id": "/redfish/v1/Systems/1/SecureBoot/"}},
    }
    sbres = {"SecureBootEnable": sb_current == "Enabled", "SecureBootCurrentBoot": sb_current,
             "SecureBootMode": sb_mode,
             "Actions": {"#SecureBoot.ResetKeys": {"target": "/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/"}}}
    if not no_sbdb:
        sbres["SecureBootDatabases"] = {"@odata.id": "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/"}
        names = ["PK", "KEK", "db", "dbx", "PKDefault", "KEKDefault", "dbDefault", "dbxDefault"]
        r["/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/"] = {
            "Members": [{"@odata.id": f"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/{n}/"} for n in names]}
        for n in names:
            base = f"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/{n}/"
            r[base] = {"DatabaseId": n, "Certificates": {"@odata.id": base + "Certificates/"}}
            certs = dbs.get(n, DB if n == "dbDefault" else [])
            r[base + "Certificates/"] = {"Members@odata.count": len(certs),
                                         "Members": [{"@odata.id": f"{base}Certificates/{i+1}/"} for i in range(len(certs))]}
            for i, (cn, exp) in enumerate(certs):
                if fail_cert == (n, i + 1):
                    continue
                r[f"{base}Certificates/{i+1}/"] = {"Subject": {"CommonName": cn}, "ValidNotAfter": exp}
    r["/redfish/v1/Systems/1/SecureBoot/"] = sbres
    return r


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        sys.stderr.write("%s %s\n" % (self.command, self.path))

    def send(self, code, body=None, headers=None):
        data = json.dumps(body or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path.rstrip("/") == "/redfish/v1/SessionService/Sessions":
            return self.send(201, {}, {"X-Auth-Token": TOKEN, "Location": "/redfish/v1/SessionService/Sessions/x/"})
        if "//" not in self.path and self.path.rstrip("/").endswith("Actions/SecureBoot.ResetKeys"):
            n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
            sys.stderr.write("RESETKEYS " + body + "\n")
            return self.send(200, {"ok": True})
        self.send(404)

    def do_PATCH(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        sys.stderr.write("PATCH %s %s\n" % (self.path, body))
        self.send(200 if "//" not in self.path else 404)

    def do_DELETE(self):
        self.send(200)

    def do_GET(self):
        if self.headers.get("X-Auth-Token") != TOKEN:
            return self.send(401)
        path = self.path.split("?")[0]
        if "//" in path:
            return self.send(404, {"error": "double slash"})
        res = resources()
        key = path if path.endswith("/") else path + "/"
        if key in res:
            return self.send(200, res[key])
        self.send(404)


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[3], sys.argv[4])
srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
