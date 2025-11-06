# This file is part of cloud-init. See LICENSE file for license information.

# TODO: Importing this file without first importing
# cloudinit.sources.azure.errors will result in a circular import.
import base64
import json
import logging
import os
import re
import textwrap
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from time import sleep, time
from typing import Callable, List, Optional, TypeVar
from xml.etree import ElementTree as ET  # nosec B405

from cloudinit import distros, subp, temp_utils, url_helper, util, version
from cloudinit.reporting import events
from cloudinit.sources.azure import errors

LOG = logging.getLogger(__name__)

BOOT_EVENT_TYPE = "boot-telemetry"
SYSTEMINFO_EVENT_TYPE = "system-info"
DIAGNOSTIC_EVENT_TYPE = "diagnostic"
COMPRESSED_EVENT_TYPE = "compressed"
azure_ds_reporter = events.ReportEventStack(
    name="azure-ds",
    description="initialize reporter for azure ds",
    reporting_enabled=True,
)

T = TypeVar("T")


def azure_ds_telemetry_reporter(func: Callable[..., T]) -> Callable[..., T]:
    def impl(*args, **kwargs):
        with events.ReportEventStack(
            name=func.__name__,
            description=func.__name__,
            parent=azure_ds_reporter,
        ):
            return func(*args, **kwargs)

    return impl


@azure_ds_telemetry_reporter
def get_boot_telemetry():
    """Report timestamps related to kernel initialization and systemd
    activation of cloud-init"""
    if not distros.uses_systemd():
        raise RuntimeError("distro not using systemd, skipping boot telemetry")

    LOG.debug("Collecting boot telemetry")
    try:
        kernel_start = float(time()) - float(util.uptime())
    except ValueError as e:
        raise RuntimeError("Failed to determine kernel start timestamp") from e

    try:
        out, _ = subp.subp(
            ["systemctl", "show", "-p", "UserspaceTimestampMonotonic"],
            capture=True,
        )
        tsm = None
        if out and "=" in out:
            tsm = out.split("=")[1]

        if not tsm:
            raise RuntimeError(
                "Failed to parse UserspaceTimestampMonotonic from systemd"
            )

        user_start = kernel_start + (float(tsm) / 1000000)
    except subp.ProcessExecutionError as e:
        raise RuntimeError(
            "Failed to get UserspaceTimestampMonotonic: %s" % e
        ) from e
    except ValueError as e:
        raise RuntimeError(
            "Failed to parse UserspaceTimestampMonotonic from systemd: %s" % e
        ) from e

    try:
        out, _ = subp.subp(
            [
                "systemctl",
                "show",
                "cloud-init-local",
                "-p",
                "InactiveExitTimestampMonotonic",
            ],
            capture=True,
        )
        tsm = None
        if out and "=" in out:
            tsm = out.split("=")[1]
        if not tsm:
            raise RuntimeError(
                "Failed to parse InactiveExitTimestampMonotonic from systemd"
            )

        cloudinit_activation = kernel_start + (float(tsm) / 1000000)
    except subp.ProcessExecutionError as e:
        raise RuntimeError(
            "Failed to get InactiveExitTimestampMonotonic: %s" % e
        ) from e
    except ValueError as e:
        raise RuntimeError(
            "Failed to parse InactiveExitTimestampMonotonic from systemd: %s"
            % e
        ) from e

    evt = events.ReportingEvent(
        BOOT_EVENT_TYPE,
        "boot-telemetry",
        "kernel_start=%s user_start=%s cloudinit_activation=%s"
        % (
            datetime.fromtimestamp(kernel_start, timezone.utc).isoformat(),
            datetime.fromtimestamp(user_start, timezone.utc).isoformat(),
            datetime.fromtimestamp(
                cloudinit_activation, timezone.utc
            ).isoformat(),
        ),
        events.DEFAULT_EVENT_ORIGIN,
    )
    events.report_event(evt)

    # return the event for unit testing purpose
    return evt


@azure_ds_telemetry_reporter
def get_system_info():
    """Collect and report system information"""
    info = util.system_info()
    evt = events.ReportingEvent(
        SYSTEMINFO_EVENT_TYPE,
        "system information",
        "cloudinit_version=%s, kernel_version=%s, variant=%s, "
        "distro_name=%s, distro_version=%s, flavor=%s, "
        "python_version=%s"
        % (
            version.version_string(),
            info["release"],
            info["variant"],
            info["dist"][0],
            info["dist"][1],
            info["dist"][2],
            info["python"],
        ),
        events.DEFAULT_EVENT_ORIGIN,
    )
    events.report_event(evt)

    # return the event for unit testing purpose
    return evt


def report_diagnostic_event(
    msg: str, *, logger_func=None
) -> events.ReportingEvent:
    """Report a diagnostic event"""
    if callable(logger_func):
        logger_func(msg)
    evt = events.ReportingEvent(
        DIAGNOSTIC_EVENT_TYPE,
        "diagnostic message",
        msg,
        events.DEFAULT_EVENT_ORIGIN,
    )
    events.report_event(evt, excluded_handler_types={"log"})

    # return the event for unit testing purpose
    return evt


def report_compressed_event(event_name, event_content):
    """Report a compressed event"""
    compressed_data = base64.encodebytes(zlib.compress(event_content))
    event_data = {
        "encoding": "gz+b64",
        "data": compressed_data.decode("ascii"),
    }
    evt = events.ReportingEvent(
        COMPRESSED_EVENT_TYPE,
        event_name,
        json.dumps(event_data),
        events.DEFAULT_EVENT_ORIGIN,
    )
    events.report_event(
        evt, excluded_handler_types={"log", "print", "webhook"}
    )

    # return the event for unit testing purpose
    return evt


@azure_ds_telemetry_reporter
def report_dmesg_to_kvp():
    """Report dmesg to KVP."""
    LOG.debug("Dumping dmesg log to KVP")
    try:
        out, _ = subp.subp(["dmesg"], decode=False, capture=True)
        report_compressed_event("dmesg", out)
    except Exception as ex:
        report_diagnostic_event(
            "Exception when dumping dmesg log: %s" % repr(ex),
            logger_func=LOG.warning,
        )


@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


@azure_ds_telemetry_reporter
def http_with_retries(
    url: str,
    *,
    headers: dict,
    data: Optional[bytes] = None,
    retry_sleep: int = 1,
    timeout_minutes: int = 20,
) -> url_helper.UrlResponse:
    """Readurl wrapper for querying wireserver.

    :param retry_sleep: Time to sleep before retrying.
    :param timeout_minutes: Retry up to specified number of minutes.
    :raises UrlError: on error fetching data.
    """
    timeout = timeout_minutes * 60 + time()

    attempt = 0
    response = None
    while not response:
        attempt += 1
        try:
            response = url_helper.readurl(
                url, headers=headers, data=data, timeout=(5, 60)
            )
            break
        except url_helper.UrlError as e:
            report_diagnostic_event(
                "Failed HTTP request with Azure endpoint %s during "
                "attempt %d with exception: %s (code=%r headers=%r)"
                % (url, attempt, e, e.code, e.headers),
                logger_func=LOG.debug,
            )
            # Raise exception if we're out of time or network is unreachable.
            # If network is unreachable:
            # - retries will not resolve the situation
            # - for reporting ready for PPS, this generally means VM was put
            #   to sleep or network interface was unplugged before we see
            #   the call complete successfully.
            if (
                time() + retry_sleep >= timeout
                or "Network is unreachable" in str(e)
            ):
                raise

        sleep(retry_sleep)

    report_diagnostic_event(
        "Successful HTTP request with Azure endpoint %s after "
        "%d attempts" % (url, attempt),
        logger_func=LOG.debug,
    )
    return response


def build_minimal_ovf(
    *,
    username: Optional[str],
    hostname: Optional[str],
    disable_ssh_password_auth: Optional[bool],
) -> bytes:
    if username:
        ns_username = f"<ns1:UserName>{username}</ns1:UserName>"
    else:
        ns_username = ""

    if disable_ssh_password_auth is None:
        ns_disable_ssh_password_auth = ""
    else:
        ns_disable_ssh_password_auth = (
            "<ns1:DisableSshPasswordAuthentication>"
            f"{str(disable_ssh_password_auth).lower()}"
            "</ns1:DisableSshPasswordAuthentication>"
        )

    ns_hostname = f"<ns1:HostName>{hostname}</ns1:HostName>"

    return textwrap.dedent(
        f"""\
        <ns0:Environment xmlns:ns0="http://schemas.dmtf.org/ovf/environment/1"
         xmlns:ns1="http://schemas.microsoft.com/windowsazure"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <ns1:ProvisioningSection>
            <ns1:Version>1.0</ns1:Version>
            <ns1:LinuxProvisioningConfigurationSet>
              <ns1:ConfigurationSetType>LinuxProvisioningConfiguration
              </ns1:ConfigurationSetType>
              {ns_username}
              {ns_disable_ssh_password_auth}
              {ns_hostname}
            </ns1:LinuxProvisioningConfigurationSet>
          </ns1:ProvisioningSection>
          <ns1:PlatformSettingsSection>
            <ns1:Version>1.0</ns1:Version>
            <ns1:PlatformSettings>
              <ns1:ProvisionGuestAgent>true</ns1:ProvisionGuestAgent>
            </ns1:PlatformSettings>
          </ns1:PlatformSettingsSection>
        </ns0:Environment>
        """
    ).encode("utf-8")


class AzureEndpointHttpClient:
    headers = {
        "x-ms-agent-name": "WALinuxAgent",
        "x-ms-version": "2012-11-30",
    }

    def __init__(self, certificate):
        self.extra_secure_headers = {
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert": certificate,
        }

    def get(self, url, secure=False) -> url_helper.UrlResponse:
        headers = self.headers
        if secure:
            headers = self.headers.copy()
            headers.update(self.extra_secure_headers)
        return http_with_retries(url, headers=headers)

    def post(
        self, url, data: Optional[bytes] = None, extra_headers=None
    ) -> url_helper.UrlResponse:
        headers = self.headers
        if extra_headers is not None:
            headers = self.headers.copy()
            headers.update(extra_headers)
        return http_with_retries(url, data=data, headers=headers)


class OpenSSLManager:
    certificate_names = {
        "private_key": "TransportPrivate.pem",
        "certificate": "TransportCert.pem",
    }

    def __init__(self):
        self.tmpdir = temp_utils.mkdtemp()
        self._certificate = None
        self.generate_certificate()

    def clean_up(self):
        util.del_dir(self.tmpdir)

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, value):
        self._certificate = value

    @azure_ds_telemetry_reporter
    def generate_certificate(self):
        LOG.debug("Generating certificate for communication with fabric...")
        if self.certificate is not None:
            LOG.debug("Certificate already generated.")
            return
        with cd(self.tmpdir):
            subp.subp(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-nodes",
                    "-subj",
                    "/CN=LinuxTransport",
                    "-days",
                    "32768",
                    "-newkey",
                    "rsa:3072",
                    "-keyout",
                    self.certificate_names["private_key"],
                    "-out",
                    self.certificate_names["certificate"],
                ]
            )
            certificate = ""
            for line in util.load_text_file(
                self.certificate_names["certificate"]
            ).splitlines():
                if "CERTIFICATE" not in line:
                    certificate += line.rstrip()
            self.certificate = certificate
        LOG.debug("New certificate generated.")

    @staticmethod
    @azure_ds_telemetry_reporter
    def _run_x509_action(action, cert):
        cmd = ["openssl", "x509", "-noout", action]
        result, _ = subp.subp(cmd, data=cert)
        return result

    @azure_ds_telemetry_reporter
    def _get_ssh_key_from_cert(self, certificate):
        pub_key = self._run_x509_action("-pubkey", certificate)
        keygen_cmd = ["ssh-keygen", "-i", "-m", "PKCS8", "-f", "/dev/stdin"]
        ssh_key, _ = subp.subp(keygen_cmd, data=pub_key)
        return ssh_key

    @azure_ds_telemetry_reporter
    def _get_fingerprint_from_cert(self, certificate):
        r"""openssl x509 formats fingerprints as so:
        'SHA1 Fingerprint=07:3E:19:D1:4D:1C:79:92:24:C6:A0:FD:8D:DA:\
        B6:A8:BF:27:D4:73\n'

        Azure control plane passes that fingerprint as so:
        '073E19D14D1C799224C6A0FD8DDAB6A8BF27D473'
        """
        raw_fp = self._run_x509_action("-fingerprint", certificate)
        eq = raw_fp.find("=")
        octets = raw_fp[eq + 1 : -1].split(":")
        return "".join(octets)

    @azure_ds_telemetry_reporter
    def _decrypt_certs_from_xml(self, certificates_xml):
        """Decrypt the certificates XML document using the our private key;
        return the list of certs and private keys contained in the doc.
        """
        tag = ET.fromstring(certificates_xml).find(".//Data")  # nosec B314
        certificates_content = tag.text
        lines = [
            b"MIME-Version: 1.0",
            b'Content-Disposition: attachment; filename="Certificates.p7m"',
            b'Content-Type: application/x-pkcs7-mime; name="Certificates.p7m"',
            b"Content-Transfer-Encoding: base64",
            b"",
            certificates_content.encode("utf-8"),
        ]
        with cd(self.tmpdir):
            out, _ = subp.subp(
                "openssl cms -decrypt -in /dev/stdin -inkey"
                " {private_key} -recip {certificate} | openssl pkcs12 -nodes"
                " -password pass:".format(**self.certificate_names),
                shell=True,
                data=b"\n".join(lines),
            )
        return out

    @azure_ds_telemetry_reporter
    def parse_certificates(self, certificates_xml):
        """Given the Certificates XML document, return a dictionary of
        fingerprints and associated SSH keys derived from the certs."""
        out = self._decrypt_certs_from_xml(certificates_xml)
        current = []
        keys = {}
        for line in out.splitlines():
            current.append(line)
            if re.match(r"[-]+END .*?KEY[-]+$", line):
                # ignore private_keys
                current = []
            elif re.match(r"[-]+END .*?CERTIFICATE[-]+$", line):
                certificate = "\n".join(current)
                ssh_key = self._get_ssh_key_from_cert(certificate)
                fingerprint = self._get_fingerprint_from_cert(certificate)
                keys[fingerprint] = ssh_key
                current = []
        return keys


class NonAzureDataSource(Exception):
    pass


class OvfEnvXml:
    NAMESPACES = {
        "ovf": "http://schemas.dmtf.org/ovf/environment/1",
        "wa": "http://schemas.microsoft.com/windowsazure",
    }

    def __init__(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hostname: Optional[str] = None,
        custom_data: Optional[bytes] = None,
        disable_ssh_password_auth: Optional[bool] = None,
        public_keys: Optional[List[dict]] = None,
        preprovisioned_vm: bool = False,
        preprovisioned_vm_type: Optional[str] = None,
        provision_guest_proxy_agent: bool = False,
    ) -> None:
        self.username = username
        self.password = password
        self.hostname = hostname
        self.custom_data = custom_data
        self.disable_ssh_password_auth = disable_ssh_password_auth
        self.public_keys: List[dict] = public_keys or []
        self.preprovisioned_vm = preprovisioned_vm
        self.preprovisioned_vm_type = preprovisioned_vm_type
        self.provision_guest_proxy_agent = provision_guest_proxy_agent

    def __eq__(self, other) -> bool:
        return self.__dict__ == other.__dict__

    @classmethod
    def parse_text(cls, ovf_env_xml: str) -> "OvfEnvXml":
        """Parser for ovf-env.xml data.

        :raises NonAzureDataSource: if XML is not in Azure's format.
        :raises errors.ReportableErrorOvfParsingException: if XML is
                unparsable or invalid.
        """
        try:
            root = ET.fromstring(ovf_env_xml)  # nosec B314
        except ET.ParseError as e:
            raise errors.ReportableErrorOvfParsingException(exception=e) from e

        # If there's no provisioning section, it's not Azure ovf-env.xml.
        if root.find("./wa:ProvisioningSection", cls.NAMESPACES) is None:
            raise NonAzureDataSource(
                "Ignoring non-Azure ovf-env.xml: ProvisioningSection not found"
            )

        instance = OvfEnvXml()
        instance._parse_linux_configuration_set_section(root)
        instance._parse_platform_settings_section(root)

        return instance

    def _find(
        self,
        node,
        name: str,
        required: bool,
        namespace: str = "wa",
    ):
        matches = node.findall(
            "./%s:%s" % (namespace, name), OvfEnvXml.NAMESPACES
        )
        if not matches:
            msg = "missing configuration for %r" % name
            LOG.debug(msg)
            if required:
                raise errors.ReportableErrorOvfInvalidMetadata(msg)
            return None
        elif len(matches) > 1:
            raise errors.ReportableErrorOvfInvalidMetadata(
                "multiple configuration matches for %r (%d)"
                % (name, len(matches))
            )

        return matches[0]

    def _parse_property(
        self,
        node,
        name: str,
        required: bool,
        decode_base64: bool = False,
        parse_bool: bool = False,
        default=None,
    ):
        matches = node.findall("./wa:" + name, OvfEnvXml.NAMESPACES)
        if not matches:
            msg = "missing configuration for %r" % name
            LOG.debug(msg)
            if required:
                raise errors.ReportableErrorOvfInvalidMetadata(msg)
            return default

        if len(matches) > 1:
            raise errors.ReportableErrorOvfInvalidMetadata(
                "multiple configuration matches for %r (%d)"
                % (name, len(matches))
            )

        value = matches[0].text

        # Empty string may be None.
        if value is None:
            value = default

        if decode_base64 and value is not None:
            value = base64.b64decode("".join(value.split()))

        if parse_bool:
            value = util.translate_bool(value)

        return value

    def _parse_linux_configuration_set_section(self, root):
        provisioning_section = self._find(
            root, "ProvisioningSection", required=True
        )
        config_set = self._find(
            provisioning_section,
            "LinuxProvisioningConfigurationSet",
            required=True,
        )

        self.custom_data = self._parse_property(
            config_set,
            "CustomData",
            decode_base64=True,
            required=False,
        )
        self.username = self._parse_property(
            config_set, "UserName", required=False
        )
        self.password = self._parse_property(
            config_set, "UserPassword", required=False
        )
        self.hostname = self._parse_property(
            config_set, "HostName", required=True
        )
        self.disable_ssh_password_auth = self._parse_property(
            config_set,
            "DisableSshPasswordAuthentication",
            parse_bool=True,
            required=False,
        )

        self._parse_ssh_section(config_set)

    def _parse_platform_settings_section(self, root):
        platform_settings_section = self._find(
            root, "PlatformSettingsSection", required=True
        )
        platform_settings = self._find(
            platform_settings_section, "PlatformSettings", required=True
        )

        self.preprovisioned_vm = self._parse_property(
            platform_settings,
            "PreprovisionedVm",
            parse_bool=True,
            default=False,
            required=False,
        )
        self.preprovisioned_vm_type = self._parse_property(
            platform_settings,
            "PreprovisionedVMType",
            required=False,
        )
        self.provision_guest_proxy_agent = self._parse_property(
            platform_settings,
            "ProvisionGuestProxyAgent",
            parse_bool=True,
            default=False,
            required=False,
        )

    def _parse_ssh_section(self, config_set):
        self.public_keys = []

        ssh_section = self._find(config_set, "SSH", required=False)
        if ssh_section is None:
            return

        public_keys_section = self._find(
            ssh_section, "PublicKeys", required=False
        )
        if public_keys_section is None:
            return

        for public_key in public_keys_section.findall(
            "./wa:PublicKey", OvfEnvXml.NAMESPACES
        ):
            fingerprint = self._parse_property(
                public_key, "Fingerprint", required=False
            )
            path = self._parse_property(public_key, "Path", required=False)
            value = self._parse_property(
                public_key, "Value", default="", required=False
            )
            ssh_key = {
                "fingerprint": fingerprint,
                "path": path,
                "value": value,
            }
            self.public_keys.append(ssh_key)
