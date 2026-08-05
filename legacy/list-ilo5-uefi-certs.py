#!/usr/bin/env python3

import argparse
import base64
import csv
import getpass
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_DATABASES = ["KEK", "KEKDefault", "db", "dbDefault"]
DEFAULT_TIMEOUT = 20


class RedfishError(Exception):
    pass


class UnsupportedFeatureError(Exception):
    pass


def normalize_host(host: str) -> str:
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"https://{host.rstrip('/')}"


def normalize_path(base_url: str, path_or_url: str) -> str:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    return urllib.parse.urljoin(f"{base_url}/", path_or_url.lstrip("/"))


def split_csv_arg(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def safe_get(mapping: dict[str, Any] | None, key: str, default: str = "") -> str:
    if not mapping:
        return default
    value = mapping.get(key, default)
    return "" if value is None else str(value)


def format_name(name: Any) -> str:
    if isinstance(name, dict):
        order = [
            ("CommonName", "CN"),
            ("Organization", "O"),
            ("OrganizationalUnit", "OU"),
            ("City", "L"),
            ("State", "ST"),
            ("Country", "C"),
        ]
        parts = [f"{label}={safe_get(name, key)}" for key, label in order if safe_get(name, key)]
        if parts:
            return ", ".join(parts)
        return json.dumps(name, ensure_ascii=False, sort_keys=True)
    if name is None:
        return ""
    return str(name)


def common_name(name: Any) -> str:
    if isinstance(name, dict):
        return safe_get(name, "CommonName")
    return ""


def pem_sha256_fingerprint(certificate_string: str) -> str:
    if not certificate_string:
        return ""

    lines = [line.strip() for line in certificate_string.splitlines()]
    b64_lines = [line for line in lines if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line]
    try:
        if not b64_lines:
            digest = hashlib.sha256(certificate_string.encode("utf-8")).hexdigest().upper()
        else:
            der = base64.b64decode("".join(b64_lines))
            digest = hashlib.sha256(der).hexdigest().upper()
    except Exception:
        digest = hashlib.sha256(certificate_string.encode("utf-8")).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def error_message_from_payload(payload: str) -> str:
    if not payload:
        return ""
    try:
        body = json.loads(payload)
    except json.JSONDecodeError:
        return payload.strip()

    error = body.get("error", {})
    message = error.get("message")
    extended = error.get("@Message.ExtendedInfo", [])
    if message:
        return str(message)
    if extended:
        first = extended[0]
        if isinstance(first, dict):
            return str(first.get("Message") or first.get("MessageId") or body)
    return json.dumps(body, ensure_ascii=False)


class RedfishClient:
    def __init__(self, host: str, user: str, password: str, verify_tls: bool, timeout: int) -> None:
        self.base_url = normalize_host(host)
        self.user = user
        self.password = password
        self.timeout = timeout
        self.session_location: str | None = None
        self.token: str | None = None

        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def request_json(
        self,
        method: str,
        path_or_url: str,
        body: dict[str, Any] | None = None,
        expected_statuses: tuple[int, ...] = (200,),
    ) -> tuple[dict[str, Any], dict[str, str], int]:
        url = normalize_path(self.base_url, path_or_url)
        headers = {"Accept": "application/json"}
        data = None

        if self.token:
            headers["X-Auth-Token"] = self.token
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8", errors="replace")
                status = response.getcode()
                response_headers = {key: value for key, value in response.headers.items()}
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            message = error_message_from_payload(payload)
            if exc.code == 404:
                raise UnsupportedFeatureError(f"{method} {url} returned HTTP 404 ({message or 'resource not found'})") from exc
            raise RedfishError(f"{method} {url} returned HTTP {exc.code} ({message or 'request failed'})") from exc
        except urllib.error.URLError as exc:
            raise RedfishError(f"{method} {url} failed ({exc.reason})") from exc

        if status not in expected_statuses:
            raise RedfishError(f"{method} {url} returned unexpected HTTP {status}")

        if not payload.strip():
            return {}, response_headers, status

        try:
            return json.loads(payload), response_headers, status
        except json.JSONDecodeError as exc:
            raise RedfishError(f"{method} {url} did not return valid JSON") from exc

    def login(self) -> None:
        _, headers, _ = self.request_json(
            "POST",
            "/redfish/v1/SessionService/Sessions",
            body={"UserName": self.user, "Password": self.password},
            expected_statuses=(200, 201),
        )
        self.token = headers.get("X-Auth-Token")
        self.session_location = headers.get("Location")
        if not self.token:
            raise RedfishError(f"{self.base_url} did not return X-Auth-Token during session creation")

    def logout(self) -> None:
        if not self.session_location or not self.token:
            return
        try:
            self.request_json("DELETE", self.session_location, expected_statuses=(200, 202, 204))
        except Exception:
            pass


def discover_database_collection_uri(client: RedfishClient, system_id: str) -> tuple[str, dict[str, Any]]:
    secure_boot, _, _ = client.request_json("GET", f"/redfish/v1/Systems/{system_id}/SecureBoot")
    collection = secure_boot.get("SecureBootDatabases", {})
    collection_uri = collection.get("@odata.id")
    if collection_uri:
        return str(collection_uri), secure_boot

    fallback_uri = f"/redfish/v1/Systems/{system_id}/SecureBoot/SecureBootDatabases"
    client.request_json("GET", fallback_uri)
    return fallback_uri, secure_boot


def collect_certificates(
    client: RedfishClient,
    host: str,
    system_id: str,
    requested_databases: list[str],
) -> dict[str, Any]:
    collection_uri, secure_boot = discover_database_collection_uri(client, system_id)
    collection, _, _ = client.request_json("GET", collection_uri)

    members = collection.get("Members", [])
    member_map: dict[str, str] = {}
    for member in members:
        member_uri = safe_get(member, "@odata.id")
        if not member_uri:
            continue
        member_id = member_uri.rstrip("/").split("/")[-1].lower()
        member_map[member_id] = member_uri

    databases: list[dict[str, Any]] = []

    for requested_name in requested_databases:
        uri = member_map.get(requested_name.lower())
        if not uri:
            uri = f"{collection_uri.rstrip('/')}/{requested_name}"

        try:
            database, _, _ = client.request_json("GET", uri)
        except UnsupportedFeatureError as exc:
            databases.append(
                {
                    "requested_name": requested_name,
                    "database_id": requested_name,
                    "name": requested_name,
                    "certificates": [],
                    "warning": str(exc),
                }
            )
            continue

        certificates_uri = safe_get(database.get("Certificates"), "@odata.id")
        if not certificates_uri:
            databases.append(
                {
                    "requested_name": requested_name,
                    "database_id": database.get("Id", requested_name),
                    "name": database.get("Name", requested_name),
                    "certificates": [],
                    "warning": "Database does not expose a Certificates collection",
                }
            )
            continue

        certificate_collection, _, _ = client.request_json("GET", certificates_uri)
        certificate_members = certificate_collection.get("Members", [])

        certificates: list[dict[str, Any]] = []
        for member in certificate_members:
            certificate_uri = safe_get(member, "@odata.id")
            if not certificate_uri:
                continue
            certificate, _, _ = client.request_json("GET", certificate_uri)
            certificate_string = safe_get(certificate, "CertificateString")
            certificates.append(
                {
                    "id": certificate.get("Id", certificate_uri.rstrip("/").split("/")[-1]),
                    "name": certificate.get("Name", ""),
                    "subject": format_name(certificate.get("Subject")),
                    "subject_cn": common_name(certificate.get("Subject")),
                    "issuer": format_name(certificate.get("Issuer")),
                    "issuer_cn": common_name(certificate.get("Issuer")),
                    "valid_not_before": safe_get(certificate, "ValidNotBefore"),
                    "valid_not_after": safe_get(certificate, "ValidNotAfter"),
                    "certificate_type": safe_get(certificate, "CertificateType"),
                    "uefi_signature_owner": safe_get(certificate, "UefiSignatureOwner"),
                    "sha256_fingerprint": pem_sha256_fingerprint(certificate_string),
                    "uri": certificate_uri,
                }
            )

        databases.append(
            {
                "requested_name": requested_name,
                "database_id": database.get("DatabaseId", database.get("Id", requested_name)),
                "name": database.get("Name", requested_name),
                "uri": uri,
                "certificate_count": len(certificates),
                "certificates": certificates,
            }
        )

    return {
        "host": host,
        "base_url": client.base_url,
        "status": "ok",
        "system_id": system_id,
        "secure_boot_enable": secure_boot.get("SecureBootEnable"),
        "secure_boot_mode": secure_boot.get("SecureBootMode"),
        "secure_boot_current_boot": secure_boot.get("SecureBootCurrentBoot"),
        "database_collection_uri": collection_uri,
        "databases": databases,
    }


def flatten_rows(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in results:
        if result.get("status") != "ok":
            rows.append(
                {
                    "host": result.get("host", ""),
                    "status": result.get("status", ""),
                    "database_id": "",
                    "database_name": "",
                    "certificate_id": "",
                    "subject_cn": "",
                    "subject": "",
                    "issuer_cn": "",
                    "issuer": "",
                    "valid_not_before": "",
                    "valid_not_after": "",
                    "uefi_signature_owner": "",
                    "sha256_fingerprint": "",
                    "message": result.get("message", ""),
                }
            )
            continue

        for database in result.get("databases", []):
            certificates = database.get("certificates", [])
            if not certificates:
                rows.append(
                    {
                        "host": result.get("host", ""),
                        "status": result.get("status", ""),
                        "database_id": database.get("database_id", ""),
                        "database_name": database.get("name", ""),
                        "certificate_id": "",
                        "subject_cn": "",
                        "subject": "",
                        "issuer_cn": "",
                        "issuer": "",
                        "valid_not_before": "",
                        "valid_not_after": "",
                        "uefi_signature_owner": "",
                        "sha256_fingerprint": "",
                        "message": database.get("warning", ""),
                    }
                )
                continue

            for certificate in certificates:
                rows.append(
                    {
                        "host": result.get("host", ""),
                        "status": result.get("status", ""),
                        "database_id": database.get("database_id", ""),
                        "database_name": database.get("name", ""),
                        "certificate_id": str(certificate.get("id", "")),
                        "subject_cn": certificate.get("subject_cn", ""),
                        "subject": certificate.get("subject", ""),
                        "issuer_cn": certificate.get("issuer_cn", ""),
                        "issuer": certificate.get("issuer", ""),
                        "valid_not_before": certificate.get("valid_not_before", ""),
                        "valid_not_after": certificate.get("valid_not_after", ""),
                        "uefi_signature_owner": certificate.get("uefi_signature_owner", ""),
                        "sha256_fingerprint": certificate.get("sha256_fingerprint", ""),
                        "message": "",
                    }
                )
    return rows


def print_text(results: list[dict[str, Any]]) -> None:
    for result in results:
        print(f"Host: {result.get('host')}")
        print(f"Status: {result.get('status')}")

        if result.get("status") != "ok":
            print(f"Message: {result.get('message', '')}")
            print()
            continue

        print(f"SecureBootEnable: {result.get('secure_boot_enable')}")
        print(f"SecureBootMode: {result.get('secure_boot_mode')}")
        print(f"SecureBootCurrentBoot: {result.get('secure_boot_current_boot')}")
        print(f"DatabaseCollection: {result.get('database_collection_uri')}")

        for database in result.get("databases", []):
            print()
            print(
                f"  Database: {database.get('database_id')} | "
                f"{database.get('name')} | certificates={database.get('certificate_count', 0)}"
            )
            warning = database.get("warning")
            if warning:
                print(f"    Warning: {warning}")
                continue

            certificates = database.get("certificates", [])
            if not certificates:
                print("    No certificates returned.")
                continue

            for certificate in certificates:
                subject = certificate.get("subject_cn") or certificate.get("subject")
                issuer = certificate.get("issuer_cn") or certificate.get("issuer")
                print(f"    - Subject: {subject}")
                if certificate.get("issuer"):
                    print(f"      Issuer: {issuer}")
                if certificate.get("valid_not_before") or certificate.get("valid_not_after"):
                    print(
                        "      Valid: "
                        f"{certificate.get('valid_not_before', '')} -> {certificate.get('valid_not_after', '')}"
                    )
                if certificate.get("uefi_signature_owner"):
                    print(f"      Owner: {certificate.get('uefi_signature_owner')}")
                if certificate.get("sha256_fingerprint"):
                    print(f"      SHA256: {certificate.get('sha256_fingerprint')}")
        print()


def write_csv_file(path: str, results: list[dict[str, Any]]) -> None:
    fieldnames = [
        "host",
        "status",
        "database_id",
        "database_name",
        "certificate_id",
        "subject_cn",
        "subject",
        "issuer_cn",
        "issuer",
        "valid_not_before",
        "valid_not_after",
        "uefi_signature_owner",
        "sha256_fingerprint",
        "message",
    ]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flatten_rows(results))


def load_hosts(args: argparse.Namespace) -> list[str]:
    hosts = list(args.host or [])
    if args.hosts_file:
        with open(args.hosts_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hosts.append(line)
    deduped: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host not in seen:
            deduped.append(host)
            seen.add(host)
    if not deduped:
        raise SystemExit("Provide at least one --host or --hosts-file")
    return deduped


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value:
            return value
    return getpass.getpass("iLO password: ")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List UEFI Secure Boot certificates and KEK databases from HPE ProLiant Gen10 via iLO5 Redfish."
    )
    parser.add_argument("--host", action="append", help="iLO hostname or IP. Repeatable.")
    parser.add_argument("--hosts-file", help="File with one iLO hostname/IP per line.")
    parser.add_argument("--user", required=True, help="iLO username.")
    parser.add_argument("--password", help="iLO password. Prefer --password-env or interactive prompt.")
    parser.add_argument(
        "--password-env",
        default="ILO_PASSWORD",
        help="Environment variable used for the password when --password is omitted. Default: ILO_PASSWORD",
    )
    parser.add_argument("--system-id", default="1", help="Redfish ComputerSystem id. Default: 1")
    parser.add_argument(
        "--databases",
        default=",".join(DEFAULT_DATABASES),
        help=f"Comma-separated Secure Boot database ids. Default: {','.join(DEFAULT_DATABASES)}",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"HTTP timeout in seconds. Default: {DEFAULT_TIMEOUT}")
    parser.add_argument("--verify-tls", action="store_true", help="Verify the iLO TLS certificate.")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout instead of human-readable text.")
    parser.add_argument("--csv", metavar="PATH", help="Write flattened CSV output to PATH.")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    hosts = load_hosts(args)
    password = resolve_password(args)
    requested_databases = split_csv_arg(args.databases)

    results: list[dict[str, Any]] = []
    exit_code = 0

    for host in hosts:
        client = RedfishClient(
            host=host,
            user=args.user,
            password=password,
            verify_tls=args.verify_tls,
            timeout=args.timeout,
        )
        try:
            client.login()
            results.append(collect_certificates(client, host, args.system_id, requested_databases))
        except UnsupportedFeatureError as exc:
            exit_code = 1
            results.append(
                {
                    "host": host,
                    "base_url": client.base_url,
                    "status": "unsupported",
                    "message": (
                        "SecureBootDatabases are not exposed through Redfish on this iLO/ROM combination. "
                        f"Details: {exc}"
                    ),
                }
            )
        except Exception as exc:
            exit_code = 1
            results.append(
                {
                    "host": host,
                    "base_url": client.base_url,
                    "status": "error",
                    "message": str(exc),
                }
            )
        finally:
            client.logout()

    if args.csv:
        write_csv_file(args.csv, results)

    if args.json:
        json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print_text(results)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
