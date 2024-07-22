"""Module for pySigma NetWitness processing pipelines"""

from typing import Dict, List, Union

from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ConvertTypeTransformation,
    FieldMappingTransformation,
)

netwitness_windows_field_mappings: Dict[str, Union[str, List[str]]] = {
    "Account": "user",
    "AgentComputer": "alias.host",
    "AllUser": "user.all",
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
    "LogonType": "logon.type",
    "NewProcessName": "process",
    "ParentImage": "process.src",
    "ParentProcessName": "process.src",
    "SourceIp": "ip.src",
    "SubjectUserName": "user.src",
    "TargetUserName": "user.dst",
}

field_transformations_to_string: List[str] = [
    "EventID",
    "LogonType",
]

field_transformations_to_number: List[str] = [
    "DestinationIpPort",
    "DestinationPort",
    "DestPort",
    "IpPort",
]


def netwitness_windows_pipeline() -> ProcessingPipeline:
    """Returns the netwitness <-> windows process pipeline

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
            identifier="netwitness_windows_transform_fields_to_string",
            transformation=ConvertTypeTransformation(target_type="str"),
            field_name_conditions=[IncludeFieldCondition(fields=field_transformations_to_string)],
            rule_conditions=[LogsourceCondition(product="windows")],
        )
    )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_windows_transform_fields_to_number",
            transformation=ConvertTypeTransformation(target_type="num"),
            field_name_conditions=[IncludeFieldCondition(fields=field_transformations_to_number)],
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
        priority=20,
        items=processing_items,
    )
