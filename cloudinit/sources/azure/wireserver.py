# This file is part of cloud-init. See LICENSE file for license information.

import logging
import textwrap
from time import sleep
from typing import List, Optional, Union

from cloudinit import distros
from cloudinit.reporting import events
from cloudinit.sources.azure.errors import InvalidGoalStateXMLException
from cloudinit.sources.helpers.azure import (
    azure_ds_reporter,
    azure_ds_telemetry_reporter,
    report_diagnostic_event,
    AzureEndpointHttpClient,
    OpenSSLManager)
from xml.etree import ElementTree as ET  # nosec B405
from xml.sax.saxutils import escape  # nosec B406

LOG = logging.getLogger(__name__)

# Default Wireserver endpoint (if not found in DHCP option 245).
DEFAULT_WIRESERVER_ENDPOINT = "168.63.129.16"

class GoalState:
    def __init__(
        self,
        unparsed_xml: Union[str, bytes],
        azure_endpoint_client: AzureEndpointHttpClient,
        need_certificate: bool = True,
    ) -> None:
        """Parses a GoalState XML string and returns a GoalState object.

        @param unparsed_xml: string representing a GoalState XML.
        @param azure_endpoint_client: instance of AzureEndpointHttpClient.
        @param need_certificate: switch to know if certificates is needed.
        @return: GoalState object representing the GoalState XML string.
        """
        self.azure_endpoint_client = azure_endpoint_client

        try:
            self.root = ET.fromstring(unparsed_xml)  # nosec B314
        except ET.ParseError as e:
            report_diagnostic_event(
                "Failed to parse GoalState XML: %s" % e,
                logger_func=LOG.warning,
            )
            raise

        self.container_id = self._text_from_xpath("./Container/ContainerId")
        self.instance_id = self._text_from_xpath(
            "./Container/RoleInstanceList/RoleInstance/InstanceId"
        )
        self.incarnation = self._text_from_xpath("./Incarnation")

        for attr in ("container_id", "instance_id", "incarnation"):
            if getattr(self, attr) is None:
                msg = "Missing %s in GoalState XML" % attr
                report_diagnostic_event(msg, logger_func=LOG.warning)
                raise InvalidGoalStateXMLException(msg)

        self.certificates_xml = None
        url = self._text_from_xpath(
            "./Container/RoleInstanceList/RoleInstance"
            "/Configuration/Certificates"
        )
        if url is not None and need_certificate:
            with events.ReportEventStack(
                name="get-certificates-xml",
                description="get certificates xml",
                parent=azure_ds_reporter,
            ):
                self.certificates_xml = self.azure_endpoint_client.get(
                    url, secure=True
                ).contents
                if self.certificates_xml is None:
                    raise InvalidGoalStateXMLException(
                        "Azure endpoint returned empty certificates xml."
                    )

    def _text_from_xpath(self, xpath):
        element = self.root.find(xpath)
        if element is not None:
            return element.text
        return None


class GoalStateHealthReporter:
    HEALTH_REPORT_XML_TEMPLATE = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="utf-8"?>
        <Health xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns:xsd="http://www.w3.org/2001/XMLSchema">
          <GoalStateIncarnation>{incarnation}</GoalStateIncarnation>
          <Container>
            <ContainerId>{container_id}</ContainerId>
            <RoleInstanceList>
              <Role>
                <InstanceId>{instance_id}</InstanceId>
                <Health>
                  <State>{health_status}</State>
                  {health_detail_subsection}
                </Health>
              </Role>
            </RoleInstanceList>
          </Container>
        </Health>
        """
    )

    HEALTH_DETAIL_SUBSECTION_XML_TEMPLATE = textwrap.dedent(
        """\
        <Details>
          <SubStatus>{health_substatus}</SubStatus>
          <Description>{health_description}</Description>
        </Details>
        """
    )

    PROVISIONING_SUCCESS_STATUS = "Ready"
    PROVISIONING_NOT_READY_STATUS = "NotReady"
    PROVISIONING_FAILURE_SUBSTATUS = "ProvisioningFailed"

    HEALTH_REPORT_DESCRIPTION_TRIM_LEN = 512

    def __init__(
        self,
        goal_state: GoalState,
        azure_endpoint_client: AzureEndpointHttpClient,
        endpoint: str,
    ) -> None:
        """Creates instance that will report provisioning status to an endpoint

        @param goal_state: An instance of class GoalState that contains
            goal state info such as incarnation, container id, and instance id.
            These 3 values are needed when reporting the provisioning status
            to Azure
        @param azure_endpoint_client: Instance of class AzureEndpointHttpClient
        @param endpoint: Endpoint (string) where the provisioning status report
            will be sent to
        @return: Instance of class GoalStateHealthReporter
        """
        self._goal_state = goal_state
        self._azure_endpoint_client = azure_endpoint_client
        self._endpoint = endpoint

    @azure_ds_telemetry_reporter
    def send_ready_signal(self) -> None:
        document = self.build_report(
            incarnation=self._goal_state.incarnation,
            container_id=self._goal_state.container_id,
            instance_id=self._goal_state.instance_id,
            status=self.PROVISIONING_SUCCESS_STATUS,
        )
        LOG.debug("Reporting ready to Azure fabric.")
        try:
            self._post_health_report(document=document)
        except Exception as e:
            report_diagnostic_event(
                "exception while reporting ready: %s" % e,
                logger_func=LOG.error,
            )
            raise

        LOG.info("Reported ready to Azure fabric.")

    @azure_ds_telemetry_reporter
    def send_failure_signal(self, description: str) -> None:
        document = self.build_report(
            incarnation=self._goal_state.incarnation,
            container_id=self._goal_state.container_id,
            instance_id=self._goal_state.instance_id,
            status=self.PROVISIONING_NOT_READY_STATUS,
            substatus=self.PROVISIONING_FAILURE_SUBSTATUS,
            description=description,
        )
        try:
            self._post_health_report(document=document)
        except Exception as e:
            msg = "exception while reporting failure: %s" % e
            report_diagnostic_event(msg, logger_func=LOG.error)
            raise

        LOG.warning("Reported failure to Azure fabric.")

    def build_report(
        self,
        incarnation: str,
        container_id: str,
        instance_id: str,
        status: str,
        substatus=None,
        description=None,
    ) -> bytes:
        health_detail = ""
        if substatus is not None:
            health_detail = self.HEALTH_DETAIL_SUBSECTION_XML_TEMPLATE.format(
                health_substatus=escape(substatus),
                health_description=escape(
                    description[: self.HEALTH_REPORT_DESCRIPTION_TRIM_LEN]
                ),
            )

        health_report = self.HEALTH_REPORT_XML_TEMPLATE.format(
            incarnation=escape(str(incarnation)),
            container_id=escape(container_id),
            instance_id=escape(instance_id),
            health_status=escape(status),
            health_detail_subsection=health_detail,
        )

        return health_report.encode("utf-8")

    @azure_ds_telemetry_reporter
    def _post_health_report(self, document: bytes) -> None:
        # Whenever report_diagnostic_event(diagnostic_msg) is invoked in code,
        # the diagnostic messages are written to special files
        # (/var/opt/hyperv/.kvp_pool_*) as Hyper-V KVP messages.
        # Hyper-V KVP message communication is done through these files,
        # and KVP functionality is used to communicate and share diagnostic
        # info with the Azure Host.
        # The Azure Host will collect the VM's Hyper-V KVP diagnostic messages
        # when cloud-init reports to fabric.
        # When the Azure Host receives the health report signal, it will only
        # collect and process whatever KVP diagnostic messages have been
        # written to the KVP files.
        # KVP messages that are published after the Azure Host receives the
        # signal are ignored and unprocessed, so yield this thread to the
        # Hyper-V KVP Reporting thread so that they are written.
        # sleep(0) is a low-cost and proven method to yield the scheduler
        # and ensure that events are flushed.
        # See HyperVKvpReportingHandler class, which is a multi-threaded
        # reporting handler that writes to the special KVP files.
        sleep(0)

        LOG.debug("Sending health report to Azure fabric.")
        url = "http://{}/machine?comp=health".format(self._endpoint)
        self._azure_endpoint_client.post(
            url,
            data=document,
            extra_headers={"Content-Type": "text/xml; charset=utf-8"},
        )
        LOG.debug("Successfully sent health report to Azure fabric")

class WALinuxAgentShim:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.openssl_manager: Optional[OpenSSLManager] = None
        self.azure_endpoint_client: Optional[AzureEndpointHttpClient] = None

    def clean_up(self):
        if self.openssl_manager is not None:
            self.openssl_manager.clean_up()

    @azure_ds_telemetry_reporter
    def eject_iso(self, iso_dev, distro: distros.Distro) -> None:
        LOG.debug("Ejecting the provisioning iso")
        try:
            distro.eject_media(iso_dev)
        except Exception as e:
            report_diagnostic_event(
                "Failed ejecting the provisioning iso: %s" % e,
                logger_func=LOG.error,
            )

    @azure_ds_telemetry_reporter
    def register_with_azure_and_fetch_data(
        self, distro: distros.Distro, pubkey_info=None, iso_dev=None
    ) -> Optional[List[str]]:
        """Gets the VM's GoalState from Azure, uses the GoalState information
        to report ready/send the ready signal/provisioning complete signal to
        Azure, and then uses pubkey_info to filter and obtain the user's
        pubkeys from the GoalState.

        @param pubkey_info: List of pubkey values and fingerprints which are
            used to filter and obtain the user's pubkey values from the
            GoalState.
        @return: The list of user's authorized pubkey values.
        """
        http_client_certificate = None
        if self.openssl_manager is None and pubkey_info is not None:
            self.openssl_manager = OpenSSLManager()
            http_client_certificate = self.openssl_manager.certificate
        if self.azure_endpoint_client is None:
            self.azure_endpoint_client = AzureEndpointHttpClient(
                http_client_certificate
            )
        goal_state = self._fetch_goal_state_from_azure(
            need_certificate=http_client_certificate is not None
        )
        ssh_keys = None
        if pubkey_info is not None:
            ssh_keys = self._get_user_pubkeys(goal_state, pubkey_info)
        health_reporter = GoalStateHealthReporter(
            goal_state, self.azure_endpoint_client, self.endpoint
        )

        if iso_dev is not None:
            self.eject_iso(iso_dev, distro=distro)

        health_reporter.send_ready_signal()
        return ssh_keys

    @azure_ds_telemetry_reporter
    def register_with_azure_and_report_failure(self, description: str) -> None:
        """Gets the VM's GoalState from Azure, uses the GoalState information
        to report failure/send provisioning failure signal to Azure.

        @param: user visible error description of provisioning failure.
        """
        if self.azure_endpoint_client is None:
            self.azure_endpoint_client = AzureEndpointHttpClient(None)
        goal_state = self._fetch_goal_state_from_azure(need_certificate=False)
        health_reporter = GoalStateHealthReporter(
            goal_state, self.azure_endpoint_client, self.endpoint
        )
        health_reporter.send_failure_signal(description=description)

    @azure_ds_telemetry_reporter
    def _fetch_goal_state_from_azure(
        self, need_certificate: bool
    ) -> GoalState:
        """Fetches the GoalState XML from the Azure endpoint, parses the XML,
        and returns a GoalState object.

        @param need_certificate: switch to know if certificates is needed.
        @return: GoalState object representing the GoalState XML
        """
        unparsed_goal_state_xml = self._get_raw_goal_state_xml_from_azure()
        return self._parse_raw_goal_state_xml(
            unparsed_goal_state_xml, need_certificate
        )

    @azure_ds_telemetry_reporter
    def _get_raw_goal_state_xml_from_azure(self) -> bytes:
        """Fetches the GoalState XML from the Azure endpoint and returns
        the XML as a string.

        @return: GoalState XML string
        """

        LOG.info("Registering with Azure...")
        url = "http://{}/machine/?comp=goalstate".format(self.endpoint)
        try:
            with events.ReportEventStack(
                name="goalstate-retrieval",
                description="retrieve goalstate",
                parent=azure_ds_reporter,
            ):
                response = self.azure_endpoint_client.get(url)  # type: ignore
        except Exception as e:
            report_diagnostic_event(
                "failed to register with Azure and fetch GoalState XML: %s"
                % e,
                logger_func=LOG.warning,
            )
            raise
        LOG.debug("Successfully fetched GoalState XML.")
        return response.contents

    @azure_ds_telemetry_reporter
    def _parse_raw_goal_state_xml(
        self,
        unparsed_goal_state_xml: Union[str, bytes],
        need_certificate: bool,
    ) -> GoalState:
        """Parses a GoalState XML string and returns a GoalState object.

        @param unparsed_goal_state_xml: GoalState XML string
        @param need_certificate: switch to know if certificates is needed.
        @return: GoalState object representing the GoalState XML
        """
        try:
            goal_state = GoalState(
                unparsed_goal_state_xml,
                self.azure_endpoint_client,  # type: ignore
                need_certificate,
            )
        except Exception as e:
            report_diagnostic_event(
                "Error processing GoalState XML: %s" % e,
                logger_func=LOG.warning,
            )
            raise
        msg = ", ".join(
            [
                "GoalState XML container id: %s" % goal_state.container_id,
                "GoalState XML instance id: %s" % goal_state.instance_id,
                "GoalState XML incarnation: %s" % goal_state.incarnation,
            ]
        )
        report_diagnostic_event(msg, logger_func=LOG.debug)
        return goal_state

    @azure_ds_telemetry_reporter
    def _get_user_pubkeys(
        self, goal_state: GoalState, pubkey_info: list
    ) -> list:
        """Gets and filters the VM admin user's authorized pubkeys.

        The admin user in this case is the username specified as "admin"
        when deploying VMs on Azure.
        See https://docs.microsoft.com/en-us/cli/azure/vm#az-vm-create.
        cloud-init expects a straightforward array of keys to be dropped
        into the admin user's authorized_keys file. Azure control plane exposes
        multiple public keys to the VM via wireserver. Select just the
        admin user's key(s) and return them, ignoring any other certs.

        @param goal_state: GoalState object. The GoalState object contains
            a certificate XML, which contains both the VM user's authorized
            pubkeys and other non-user pubkeys, which are used for
            MSI and protected extension handling.
        @param pubkey_info: List of VM user pubkey dicts that were previously
            obtained from provisioning data.
            Each pubkey dict in this list can either have the format
            pubkey['value'] or pubkey['fingerprint'].
            Each pubkey['fingerprint'] in the list is used to filter
            and obtain the actual pubkey value from the GoalState
            certificates XML.
            Each pubkey['value'] requires no further processing and is
            immediately added to the return list.
        @return: A list of the VM user's authorized pubkey values.
        """
        ssh_keys = []
        if (
            goal_state.certificates_xml is not None
            and pubkey_info is not None
            and self.openssl_manager is not None
        ):
            LOG.debug("Certificate XML found; parsing out public keys.")
            keys_by_fingerprint = self.openssl_manager.parse_certificates(
                goal_state.certificates_xml
            )
            ssh_keys = self._filter_pubkeys(keys_by_fingerprint, pubkey_info)
        return ssh_keys

    @staticmethod
    def _filter_pubkeys(keys_by_fingerprint: dict, pubkey_info: list) -> list:
        """Filter and return only the user's actual pubkeys.

        @param keys_by_fingerprint: pubkey fingerprint -> pubkey value dict
            that was obtained from GoalState Certificates XML. May contain
            non-user pubkeys.
        @param pubkey_info: List of VM user pubkeys. Pubkey values are added
            to the return list without further processing. Pubkey fingerprints
            are used to filter and obtain the actual pubkey values from
            keys_by_fingerprint.
        @return: A list of the VM user's authorized pubkey values.
        """
        keys = []
        for pubkey in pubkey_info:
            if "value" in pubkey and pubkey["value"]:
                keys.append(pubkey["value"])
            elif "fingerprint" in pubkey and pubkey["fingerprint"]:
                fingerprint = pubkey["fingerprint"]
                if fingerprint in keys_by_fingerprint:
                    keys.append(keys_by_fingerprint[fingerprint])
                else:
                    LOG.warning(
                        "ovf-env.xml specified PublicKey fingerprint "
                        "%s not found in goalstate XML",
                        fingerprint,
                    )
            else:
                LOG.warning(
                    "ovf-env.xml specified PublicKey with neither "
                    "value nor fingerprint: %s",
                    pubkey,
                )

        return keys


@azure_ds_telemetry_reporter
def get_metadata_from_fabric(
    endpoint: str,
    distro: distros.Distro,
    pubkey_info: Optional[List[str]] = None,
    iso_dev: Optional[str] = None,
):
    shim = WALinuxAgentShim(endpoint=endpoint)
    try:
        return shim.register_with_azure_and_fetch_data(
            distro=distro, pubkey_info=pubkey_info, iso_dev=iso_dev
        )
    finally:
        shim.clean_up()


@azure_ds_telemetry_reporter
def report_failure_to_fabric(endpoint: str, *, encoded_report: str):
    shim = WALinuxAgentShim(endpoint=endpoint)
    try:
        shim.register_with_azure_and_report_failure(description=encoded_report)
    finally:
        shim.clean_up()


def dhcp_log_cb(interface: str, out: str, err: str) -> None:
    report_diagnostic_event(
        f"dhcp client stdout for interface={interface}: {out}",
        logger_func=LOG.debug,
    )
    report_diagnostic_event(
        f"dhcp client stderr for interface={interface}: {err}",
        logger_func=LOG.debug,
    )
