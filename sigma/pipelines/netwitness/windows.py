"""Module for pySigma NetWitness processing pipelines"""

from typing import Dict, List, Union

from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation

from sigma.pipelines.netwitness.schemas import PipelinePriority

netwitness_windows_field_mappings: Dict[str, Union[str, List[str]]] = {
    "Account": "user",
    "AgentComputer": "alias.host",
    "AllUser": "user.all",
    "AuthenticationPackageName": "auth.method",
    "CommandLine": "param",
    "DestinationIp": "ip.dst",
    "DestinationIpAddress": "ip.dst",
    "DestinationIpPort": "ip.dstport",
    "DestinationPort": "ip.dstport",
    "DestPort": "ip.dstport",
    "Domain": "domain",
    "EventID": "reference.id",
    "Image": "process",
    "IpAddress": "host.src",
    "IpPort": "ip.srcport",
    "LogonProcessName": "process",
    "LogonType": "logon.type",
    "NewProcessName": "process",
    "ParentImage": "process.src",
    "ParentProcessName": "process.src",
    "SourceIp": "ip.src",
    "SubjectUserName": "user.src",
    "TargetUserName": "user.dst",
}


def netwitness_windows_pipeline() -> ProcessingPipeline:
    """Returns the NetWitness <-> Windows process pipeline

    Returns:
        ProcessingPipeline: Windows processing pipeline
    """

    processing_items: list[ProcessingItem] = []

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_windows_add_process_creation_condition",
            transformation=AddConditionTransformation({"EventID": "4688"}),
            rule_conditions=[logsource_windows_process_creation()],
        )
    )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_windows_add_device_type_condition",
            transformation=AddConditionTransformation({"device.type": "windows"}),
            rule_conditions=[LogsourceCondition(product="windows")],
        )
    )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_windows_field_mapping",
            transformation=FieldMappingTransformation(netwitness_windows_field_mappings),
            rule_conditions=[LogsourceCondition(product="windows")],
        )
    )

    return ProcessingPipeline(
        name="NetWitness Windows log source conditions",
        allowed_backends=frozenset({"netwitness"}),
        priority=PipelinePriority.FIRST.value,
        items=processing_items,
    )
