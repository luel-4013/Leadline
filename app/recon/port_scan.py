"""
Leadline - Port Scan Phase
TCP connect scan against a curated list of commonly-exposed ports, with
banner grabbing for service/version identification and certificate
inspection on ports that speak TLS.

This is a connect() scan (completes the full TCP handshake), not a raw
SYN/stealth scan -- no elevated privileges required, and it's the standard,
most detectable-but-simplest form of port scanning.
"""
import asyncio
import random
import ssl
from typing import Dict, Any, List, Optional

from app.recon.base import BaseReconPhase
from app.config import settings


# port -> (service name, speaks TLS immediately on connect)
#
# Organized by category rather than one flat block so the list stays
# maintainable. This is a curated set of ports that commonly have a real
# service behind them, not a 1-65535 sweep -- a full sweep would make each
# scan take dramatically longer for very little added signal (the ports
# actually worth checking are a well-understood, fairly small set), and
# would look far more aggressive to any WAF/IDS watching.
#
# A handful of ports are legitimately reused for different services
# depending on deployment (e.g. 9093 is Prometheus Alertmanager's default
# AND a common Kafka SSL listener choice) -- each appears exactly once
# below, resolved to the more canonical/common default.
COMMON_PORTS: Dict[int, tuple] = {}

def _add(ports_and_services):
    for port, service, is_tls in ports_and_services:
        COMMON_PORTS[port] = (service, is_tls)

# -- Standard / legacy services --
_add([
    (7, "echo", False), (19, "chargen", False), (20, "ftp-data", False), (21, "ftp", False),
    (22, "ssh", False), (23, "telnet", False), (25, "smtp", False), (37, "time", False),
    (43, "whois", False), (53, "dns", False), (67, "dhcp", False), (69, "tftp", False),
    (79, "finger", False), (80, "http", False), (88, "kerberos", False), (110, "pop3", False),
    (111, "rpcbind", False), (113, "ident", False), (119, "nntp", False), (123, "ntp", False),
    (135, "msrpc", False), (137, "netbios-ns", False), (138, "netbios-dgm", False),
    (139, "netbios-ssn", False), (143, "imap", False), (161, "snmp", False), (162, "snmptrap", False),
    (177, "xdmcp", False), (179, "bgp", False), (194, "irc", False), (199, "smux", False),
    (389, "ldap", False), (427, "svrloc", False), (443, "https", True), (444, "snpp", False),
    (445, "smb", False), (464, "kpasswd", False), (465, "smtps", True), (497, "retrospect", False),
    (500, "isakmp", False), (512, "exec", False), (513, "login", False), (514, "syslog", False),
    (515, "printer", False), (520, "rip", False), (523, "ibm-db2", False), (540, "uucp", False),
    (548, "afp", False), (554, "rtsp", False), (587, "smtp-submission", False), (591, "filemaker-http", False),
    (593, "http-rpc-epmap", False), (623, "ipmi", False), (631, "ipp", False), (636, "ldaps", True),
    (646, "ldp", False), (873, "rsync", False), (902, "vmware-auth", False), (989, "ftps-data", True),
    (990, "ftps", True), (993, "imaps", True), (995, "pop3s", True),
])

# -- Windows / Active Directory --
_add([
    (1025, "msrpc-alt", False), (1026, "msrpc-alt", False), (1027, "msrpc-alt", False),
    (1028, "msrpc-alt", False), (3268, "ldap-gc", False), (3269, "ldaps-gc", True),
    (3389, "rdp", False), (5722, "dfsr", False), (5985, "winrm-http", False),
    (5986, "winrm-https", True), (9389, "adws", False),
])

# -- Databases / caches / search --
_add([
    (1433, "mssql", False), (1434, "mssql-browser", False), (1521, "oracle", False),
    (1830, "oracle-oms", False), (2181, "zookeeper", False), (2379, "etcd-client", False),
    (2380, "etcd-peer", False), (3050, "firebird", False), (3306, "mysql", False),
    (4333, "msql", False), (5342, "qpasa", False), (5432, "postgresql", False),
    (5433, "postgresql-alt", False), (5984, "couchdb", False), (6379, "redis", False),
    (6380, "redis-tls", True), (7000, "cassandra", False), (7199, "cassandra-jmx", False),
    (7473, "neo4j-https", True), (7474, "neo4j-http", False), (7687, "neo4j-bolt", False),
    (8086, "influxdb", False), (8087, "influxdb-alt", False), (8091, "couchbase-admin", False),
    (8529, "arangodb", False), (9042, "cassandra-cql", False), (9160, "cassandra-thrift", False),
    (9200, "elasticsearch", False), (9300, "elasticsearch-transport", False), (11211, "memcached", False),
    (15672, "rabbitmq-mgmt", False), (16379, "redis-cluster", False), (18080, "clickhouse-http", False),
    (27017, "mongodb", False), (27018, "mongodb-shard", False), (27019, "mongodb-config", False),
    (28015, "rethinkdb", False), (28017, "mongodb-http", False), (50000, "sap", False),
    (50070, "hadoop-namenode", False),
])

# -- Message queues / streaming --
_add([
    (1883, "mqtt", False), (4369, "epmd-erlang", False), (5222, "xmpp-client", False),
    (5223, "xmpp-client-tls", True), (5269, "xmpp-server", False), (5671, "amqp-tls", True),
    (5672, "amqp", False), (8883, "mqtt-tls", True), (9092, "kafka", False),
    (61613, "stomp", False), (61616, "activemq", False),
])

# -- Containers / orchestration / infra automation --
_add([
    (2222, "ssh-alt", False), (2375, "docker", False), (2376, "docker-tls", True),
    (2377, "docker-swarm", False), (4243, "docker-alt", False), (4646, "nomad", False),
    (6443, "kubernetes-api", True), (8001, "kubernetes-dashboard", False), (8200, "vault", True),
    (8500, "consul", False), (8600, "consul-dns", False), (10250, "kubelet", True),
    (10255, "kubelet-readonly", False), (10256, "kube-proxy", False),
])

# -- Monitoring / observability --
_add([
    (5601, "kibana", False), (8428, "victoriametrics", False), (9090, "prometheus", False),
    (9093, "alertmanager", False), (9100, "node-exporter", False), (10050, "zabbix-agent", False),
    (10051, "zabbix-server", False), (12900, "elastic-apm", False),
])

# -- Web servers / dev servers / proxies --
_add([
    (2082, "cpanel", False), (2083, "cpanel-ssl", True), (2086, "whm", False),
    (2087, "whm-ssl", True), (2095, "webmail", False), (2096, "webmail-ssl", True),
    (3000, "dev-http", False), (3001, "dev-http", False), (4000, "dev-http", False),
    (4200, "dev-http", False), (4443, "https-alt", True), (5000, "dev-http", False),
    (5001, "dev-http", False), (6000, "x11", False), (7070, "http-alt", False),
    (7777, "http-alt", False), (8000, "http-alt", False), (8008, "http-alt", False),
    (8009, "tomcat-ajp", False), (8080, "http-proxy", False), (8081, "http-alt", False),
    (8088, "http-alt", False), (8090, "http-alt", False), (8181, "http-alt", False),
    (8443, "https-alt", True), (8888, "http-alt", False), (8983, "solr", False),
    (9000, "php-fpm/dev", False), (9001, "http-alt", False), (9080, "http-alt", False),
    (9443, "https-alt", True), (9999, "http-alt", False),
])

# -- CI/CD, version control, admin panels --
_add([
    (3690, "svn", False), (8069, "odoo", False), (8140, "puppet", False),
    (9418, "git", False), (9990, "wildfly-mgmt", False), (10000, "webmin", False),
])

# -- Remote access / file transfer / misc --
_add([
    (2049, "nfs", False), (2121, "ftp-alt", False), (5800, "vnc-http", False),
    (5900, "vnc", False), (5901, "vnc-alt", False), (6001, "x11-alt", False), (6667, "irc", False),
])

# -- App servers --
_add([
    (1099, "java-rmi", False), (4848, "glassfish-admin", True), (7001, "weblogic", False),
    (7002, "weblogic-tls", True), (8005, "tomcat-shutdown", False),
])

# Directly-internet-reachable instances of these are usually worth flagging
# above "info" -- databases/caches/admin interfaces with no HTTP layer in
# front of them are a common real-world finding.
HIGH_RISK_PORTS = {
    23, 111, 137, 139, 161, 445, 512, 513, 514,               # legacy/plaintext/no-auth-by-default
    1433, 1521, 2181, 2375, 2379, 3306, 3389, 5432, 5900, 5985,
    5984, 6379, 6380, 7199, 8200, 8500, 9042, 9090, 9200, 9300, 10250,
    11211, 27017, 27018, 27019,                                 # databases/caches/orchestration control planes
}

HTTP_LIKE_SERVICES = {
    "http", "http-alt", "http-proxy", "dev-http", "php-fpm/dev", "tomcat-ajp",
    "kibana", "solr", "couchdb", "couchdb-alt", "prometheus", "consul",
    "kubernetes-dashboard", "cpanel", "whm", "webmail", "webmin",
}



class PortScanPhase(BaseReconPhase):
    """TCP connect scan of common ports, with banner grab + TLS cert info."""

    name = "port_scan"
    order = 3
    description = "TCP connect scan of common ports with banner grabbing and TLS certificate inspection"

    async def execute(self) -> Dict[str, Any]:
        host = self._extract_host(self.target_url)

        # Prefer an IP host_intel already resolved (avoids a second DNS
        # round-trip and is more accurate if the domain has multiple A
        # records); fall back to the raw host if host_intel didn't run or
        # didn't resolve anything.
        host_intel = self.context.get("host_intel") or {}
        resolved_ips = host_intel.get("resolved_ips") or []
        scan_target = resolved_ips[0] if resolved_ips else host

        config = self._scan_config()
        evasion_enabled = config.get("evasion_enabled", True)
        concurrency = max(1, settings.PORT_SCAN_CONCURRENCY)
        semaphore = asyncio.Semaphore(concurrency)

        results: Dict[int, Dict[str, Any]] = {}

        async def scan_one(port: int, service_name: str, is_tls: bool):
            async with semaphore:
                if evasion_enabled:
                    # Deliberately much smaller than the full-request
                    # _delay() (0.5s+ default) -- spacing ~45 port probes at
                    # that rate would take 20-40+ seconds on its own. This
                    # still avoids firing every connection in the same
                    # instant, which is the more obvious scan signature.
                    await asyncio.sleep(random.uniform(0.02, 0.15))
                res = await self._scan_port(scan_target, port, service_name, is_tls)
                if res is not None:
                    results[port] = res

        await asyncio.gather(*(
            scan_one(port, name, is_tls) for port, (name, is_tls) in COMMON_PORTS.items()
        ))

        open_ports = dict(sorted(results.items()))
        self._generate_findings(host, scan_target, open_ports)

        return {
            "host_scanned": scan_target,
            "ports_checked": len(COMMON_PORTS),
            "open_ports": open_ports,
            "status": "completed",
        }

    # ------------------------------------------------------------------ #

    async def _scan_port(self, host: str, port: int, service_name: str, is_tls: bool) -> Optional[Dict[str, Any]]:
        timeout = settings.PORT_SCAN_TIMEOUT
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None  # closed, filtered, or unreachable -- not an error, just not open

        info: Dict[str, Any] = {"service": service_name, "state": "open"}
        try:
            if is_tls:
                info["tls"] = await self._grab_tls_info(host, port, timeout)
            else:
                banner = await self._grab_banner(reader, writer, host, service_name, timeout)
                if banner:
                    info["banner"] = banner
                    version_guess = self._guess_version(banner)
                    if version_guess:
                        info["version_guess"] = version_guess
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return info

    async def _grab_banner(self, reader, writer, host: str, service_name: str, timeout: float) -> Optional[str]:
        read_timeout = min(timeout, 2.0)
        try:
            # Several services (SSH, FTP, SMTP, POP3, IMAP) send a greeting
            # unprompted right after the handshake.
            data = await asyncio.wait_for(reader.read(256), timeout=read_timeout)
            if data:
                return data.decode(errors="replace").strip()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            pass
        # No unprompted banner -- try one protocol-appropriate probe.
        try:
            if service_name in HTTP_LIKE_SERVICES:
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            else:
                probe = b"\r\n"
            writer.write(probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=read_timeout)
            return data.decode(errors="replace").strip() if data else None
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            return None

    def _guess_version(self, banner: str) -> Optional[str]:
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()[:200]
        first_line = banner.splitlines()[0] if banner.splitlines() else banner
        return first_line[:200] if first_line else None

    async def _grab_tls_info(self, host: str, port: int, timeout: float) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # inspecting the cert, not trusting it -- self-signed/expired targets are common and still worth reporting on
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return {"error": "TLS handshake completed but no SSL object was exposed"}
            # NOTE: getpeercert() (binary_form=False, the parsed-dict form)
            # returns {} when verify_mode is CERT_NONE -- it only parses the
            # cert if validation succeeded. binary_form=True still returns
            # the raw DER bytes regardless, which is what actually lets us
            # inspect self-signed/expired/hostname-mismatched certs.
            der_cert = ssl_object.getpeercert(binary_form=True)
            if not der_cert:
                return {"error": "peer presented no certificate"}
            cert_info = self._parse_der_cert(der_cert)
            cert_info["cipher"] = ssl_object.cipher()[0] if ssl_object.cipher() else None
            cert_info["tls_version"] = ssl_object.version()
            return cert_info
        except Exception as e:
            return {"error": f"TLS handshake failed: {e}"}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _parse_der_cert(self, der_bytes: bytes) -> Dict[str, Any]:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID, ExtensionOID

        cert = x509.load_der_x509_certificate(der_bytes, default_backend())

        def _attr(name, oid):
            try:
                return name.get_attributes_for_oid(oid)[0].value
            except IndexError:
                return None

        sans: List[str] = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = list(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass

        # cryptography >=42 deprecated the naive not_valid_before/after
        # properties in favor of timezone-aware *_utc variants; support both
        # since the exact installed version isn't pinned (comes in
        # transitively via python-jose[cryptography]).
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

        return {
            "subject_cn": _attr(cert.subject, NameOID.COMMON_NAME),
            "issuer_cn": _attr(cert.issuer, NameOID.COMMON_NAME),
            "issuer_org": _attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "san_dns_names": sans,
            "serial_number": str(cert.serial_number),
            "is_self_signed": cert.issuer == cert.subject,
        }

    # ------------------------------------------------------------------ #

    def _generate_findings(self, host: str, scan_target: str, open_ports: Dict[int, Dict[str, Any]]):
        if not open_ports:
            return

        summary_lines = [f"{port}/{info['service']}" for port, info in open_ports.items()]
        self.add_finding(
            finding_type="open_ports", severity="info",
            title=f"{len(open_ports)} open port(s) found",
            description=f"Open: {', '.join(summary_lines)}",
            location=scan_target, evidence=", ".join(summary_lines),
            metadata={"open_ports": open_ports},
        )

        for port, info in open_ports.items():
            if port in HIGH_RISK_PORTS:
                self.add_finding(
                    finding_type="high_risk_open_port", severity="high",
                    title=f"Directly-reachable {info['service']} on port {port}",
                    description=(
                        f"Port {port} ({info['service']}) accepted a connection directly from the internet. "
                        "Databases, caches, and admin interfaces exposed without a proxy/firewall in front of "
                        "them are a common path to unauthorized access."
                    ),
                    location=f"{scan_target}:{port}",
                    evidence=info.get("banner", "")[:300] or f"service={info['service']}",
                    remediation=f"Restrict port {port} to internal networks/VPN, or place it behind authentication and a firewall.",
                    metadata={"port": port, "info": info},
                )

            tls = info.get("tls")
            if tls and not tls.get("error"):
                if tls.get("is_self_signed"):
                    self.add_finding(
                        finding_type="self_signed_certificate", severity="low",
                        title=f"Self-signed certificate on port {port}",
                        description=f"The TLS certificate on port {port} is self-signed (issuer == subject: {tls.get('issuer_cn')}).",
                        location=f"{scan_target}:{port}", evidence=str(tls),
                        remediation="Use a certificate from a trusted CA for any publicly-reachable service.",
                    )
