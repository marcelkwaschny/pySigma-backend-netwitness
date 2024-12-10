"""Module for pySigma NetWitness processing pipelines"""

from typing import Dict, List, Tuple, Union

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation

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
    "crlevel": "severity",
    "devid": "hardware.id",
    "devname": "event.source",
    "direction": "attack.direction",
    "dst_int": "dinterface",
    "dst_port": "ip.dstport",
    "dstcountry": "country.dst",
    "dstintf": "dinterface",
    "dstintfrole": "dstintfrole",
    "dstip": "ip.dst",
    "dstport": "ip.dstport",
    "eventtype": "category",
    "filename": "filename",
    "group": "group",
    "hostname": "alias.host",
    "level": "severity",
    "logid": "reference.id",
    "msg": "event.desc",
    "poluuid": "reference.id2",
    "pri": "severity",
    "profile": "rule.name",
    "qname": "web.domain",
    "remip": "ip.dst",
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
    "subtype": "category",
    "trandisp": "context",
    "type": "event.type",
    "user": "user.dst",
    "utmaction": "event.state",
    "vd": "vsys",
    "virus": "virusname",
}

logsource_transformation_mappings: List[Tuple[str, LogsourceCondition, Dict]] = [
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
            identifier="netwitness_fortinet_field_mapping",
            transformation=FieldMappingTransformation(netwitness_fortinet_field_mappings),
            rule_conditions=[LogsourceCondition(product="fortinet")],
        )
    )

    return ProcessingPipeline(
        name="NetWitness Fortinet log source conditions",
        allowed_backends=frozenset({"netwitness"}),
        priority=2,
        items=processing_items,
    )
