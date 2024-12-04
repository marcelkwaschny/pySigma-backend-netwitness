"""Module for pySigma NetWitness processing pipelines"""

from typing import Dict, List, Tuple, Union

from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ConvertTypeTransformation,
    FieldMappingTransformation,
)

netwitness_fortinet_field_mappings: Dict[str, Union[str, List[str]]] = {
    "DestinationPort": "ip.dstport",
    "NetwitnessDirection": "direction",
    "action": "action",
    "agent": "user.agent",
    "analyticscksum": "checksum",
    "app": "obj.name",
    "attack": "policy.name",
    "attackid": "sig.id",
    "catdesc": "filter",
    "classifier": "filter",
    "client_ip": "ip.src",
    "crlevel": "severity",
    "device_id": "hardware.id",
    "devid": "hardware.id",
    "devname": "event.source",
    "direction": "attack.direction",
    "disposition": "disposition",
    "domain": "domain",
    "dst_int": "dinterface",
    "dst_ip": "ip.dst",
    "dst_port": "ip.dstport",
    "dstcountry": "country.dst",
    "dstintf": "dinterface",
    "dstintfrole": "dstintfrole",
    "dstip": "ip.dst",
    "dstport": "ip.dstport",
    "eventtype": "category",
    "filename": "filename",
    "from": "email.src",
    "group": "group",
    "hostname": "alias.host",
    "level": "severity",
    "logid": "reference.id",
    "mailer": "client",
    "msg": "event.desc",
    "poluuid": "reference.id2",
    "pri": "severity",
    "profile": "rule.name",
    "qname": "web.domain",
    "remip": "ip.dst",
    "resolved": "context",
    "sentbyte": "bytes.src",
    "severity": "severity",
    "src_int": "sinterface",
    "src_port": "ip.srcport",
    "srccountry": "country.src",
    "srcintf": "sinterface",
    "srcintfrole": "srcintfrole",
    "srcip": "ip.src",
    "srcname": "host.src",
    "srcport": "ip.srcport",
    "status": "event.state",
    "subject": "subject",
    "subtype": "category",
    "to": "email.dst",
    "trandisp": "context",
    "type": "event.type",
    "ui": "user.dst",
    "user": "user.dst",
    "utmaction": "event.state",
    "vd": "vsys",
    "virus": "virusname",
}

field_transformations_to_string: List[str] = [
    "logid",
    "poluuid",
]

field_transformations_to_number: List[str] = [
    "DestinationPort",
    "dst_port",
    "dstport",
    "src_port",
    "srcport",
]

logsource_transformation_mappings: List[Tuple[str, LogsourceCondition, Dict]] = [
    ("fortimail", LogsourceCondition(product="fortimail"), {"device.type": "fortinetfortimail"}),
    ("fortinet", LogsourceCondition(product="fortinet"), {"device.type": "fortinet"}),
    ("fortinet_firewall", LogsourceCondition(product="fortinet", service="firewall"), {"category": "forward"}),
    ("fortinet_user", LogsourceCondition(product="fortinet", service="user"), {"category": "user"}),
    ("fortinet_app_ctrl", LogsourceCondition(product="fortinet", service="app-ctrl"), {"category": "app-ctrl"}),
    ("fortinet_webfilter", LogsourceCondition(product="fortinet", service="webfilter"), {"category": "webfilter"}),
    ("fortinet_wad", LogsourceCondition(product="fortinet", service="wad"), {"category": "wad"}),
    ("fortinet_vpn", LogsourceCondition(product="fortinet", service="vpn"), {"category": "vpn"}),
    ("fortinet_ssl", LogsourceCondition(product="fortinet", service="ssl"), {"category": "ssl"}),
    ("fortinet_local", LogsourceCondition(product="fortinet", service="local"), {"category": "local"}),
    ("fortinet_ips", LogsourceCondition(product="fortinet", service="ips"), {"category": "ips"}),
    ("fortinet_voip", LogsourceCondition(product="fortinet", service="voip"), {"category": "voip"}),
    (
        "fortinet_fortisandbox",
        LogsourceCondition(product="fortinet", service="fortisandbox"),
        {"category": "fortisandbox"},
    ),
    ("fortinet_virus", LogsourceCondition(product="fortinet", service="virus"), {"category": "virus"}),
    ("fortinet_dns", LogsourceCondition(product="fortinet", service="dns"), {"category": "dns"}),
    ("fortinet_endpoint", LogsourceCondition(product="fortinet", service="endpoint"), {"category": "endpoint"}),
]


def netwitness_fortinet_pipeline() -> ProcessingPipeline:
    """Returns the netwitness <-> fortinet process pipeline

    Returns:
        ProcessingPipeline: Fortinet processing pipeline
    """

    processing_items: list[ProcessingItem] = []

    for identifier, logsource_condition, add_transformation in logsource_transformation_mappings:
        processing_items.append(
            ProcessingItem(
                identifier=f"netwitness_fortinet_add_{identifier}_condition",
                transformation=AddConditionTransformation(add_transformation),
                rule_conditions=[logsource_condition],
            )
        )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_fortinet_transform_fields_to_string",
            transformation=ConvertTypeTransformation(target_type="str"),
            field_name_conditions=[IncludeFieldCondition(fields=field_transformations_to_string)],
            rule_conditions=[LogsourceCondition(product="fortinet")],
        )
    )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_fortinet_transform_fields_to_number",
            transformation=ConvertTypeTransformation(target_type="num"),
            field_name_conditions=[IncludeFieldCondition(fields=field_transformations_to_number)],
            rule_conditions=[LogsourceCondition(product="fortinet")],
        )
    )

    processing_items.append(
        ProcessingItem(
            identifier="netwitness_fortinet_field_mapping",
            transformation=FieldMappingTransformation(netwitness_fortinet_field_mappings),
            rule_conditions=[LogsourceCondition(product="fortinet")],
        )
    )

    return ProcessingPipeline(
        name="NetWitness Fortinet log source conditions",
        allowed_backends=frozenset({"netwitness"}),
        priority=20,
        items=processing_items,
    )
