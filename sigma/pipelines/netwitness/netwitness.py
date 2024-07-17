"""Module for pySigma NetWitness processing pipelines"""

from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, AddConditionTransformation, ConvertTypeTransformation
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition


def netwitness_windows_pipeline() -> ProcessingPipeline:
    """Returns the netwitness <-> windows process pipeline

    Returns:
        ProcessingPipeline: Windows processing pipeline
    """

    processing_items: list[ProcessingItem] = []

    processing_items.append(ProcessingItem(
        identifier="netwitness_windows_add_process_creation_condition",
        transformation=AddConditionTransformation(
            {
                "EventID": "4688",
            }
        ),
        rule_conditions=[logsource_windows_process_creation()],
    ))

    processing_items.append(ProcessingItem(
        identifier="netwitness_windows_transform_eventid_to_string",
        transformation=ConvertTypeTransformation(
            target_type="str"
        ),
        field_name_conditions=[
            IncludeFieldCondition(fields=["EventID"])
        ],
        rule_conditions=[LogsourceCondition(product="windows")],
    ))

    processing_items.append(ProcessingItem(
        identifier="netwitness_windows_field_mapping",
        transformation=FieldMappingTransformation(
            {
                "AgentComputer": "alias.host",
                "AllUser": "user.all",
                "CommandLine": "param",
                "Domain": "domain",
                "EventID": "reference.id",
                "Image": "process",
                "LogonType": "logon.type",
                "NewProcessName": "process",
                "ParentImage": "process.src",
                "ParentProcessName": "process.src",
                "SubjectUserName": "user.src",
                "TargetUserName": "user.dst"
            }
        ),
        rule_conditions=[LogsourceCondition(product="windows")],
    ))

    return ProcessingPipeline(
        name="NetWitness Windows log source conditions",
        allowed_backends=frozenset({"netwitness"}),
        priority=20,
        items=processing_items
    )
