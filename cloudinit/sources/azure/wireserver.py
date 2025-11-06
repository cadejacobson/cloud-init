# This file is part of cloud-init. See LICENSE file for license information.

import logging
import textwrap
from time import sleep
from typing import Union

from cloudinit.reporting import events
from cloudinit.sources.helpers.azure import (
    azure_ds_reporter,
    azure_ds_telemetry_reporter,
    report_diagnostic_event,
    AzureEndpointHttpClient,
    InvalidGoalStateXMLException)
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