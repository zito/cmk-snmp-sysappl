#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:sta:si:sw=4:sts=4:et:

from .agent_based_api.v1 import (
        exists,
        OIDBytes,
        OIDEnd,
        register,
        Result,
        Service,
        SNMPTree,
        State
    )
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, StringByteTable
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List


Section = Dict[str, Any]

def _snmp_datetime(tm: bytes) -> datetime:
    return datetime(256 * tm[0] + tm[1], tm[2], tm[3],
            tm[4], tm[5], tm[6],
            100000 * tm[7])

def _snmp_run_state(code: str) -> str:
    return {'1': 'running',
            '2': 'runnable',
            '3': 'waiting',
            '4': 'exiting',
            '5': 'other'}[code]

def parse_snmp_sysappl(string_table: List[StringByteTable]) -> Section:
    (appl_names, appl_run) = string_table
    appl_run2 = defaultdict(dict)
    for (k, started, state) in appl_run:
        (k_inst, k_run) = k.split('.', 2)
        appl_run2[k_inst][k_run] = (_snmp_datetime(started), _snmp_run_state(state))
    parsed = dict([(name, (k_inst, appl_run2[k_inst])) for (k_inst, name) in appl_names ])
    return parsed

def discover_snmp_sysappl(section: Section) -> DiscoveryResult:
    for key in section.keys():
        if section[key][1]:
            yield Service(item=key)
 
def check_snmp_sysappl(item: str, params: Dict[str, Any], section: Section) -> CheckResult:
    if item in section:
        d = section[item]
        if d[1]:
            yield Result(state=State.OK,
                    summary=f"running ({len(d[1])})",
                    details=f"installation index {d[0]}")
            for instance, (started, state)  in d[1].items():
                yield Result(state=State.OK,
                        notice=f"process {instance}: {state}, started {started}")
        else:
            yield Result(state=State.CRIT,
                    summary=f"not running",
                    details=f"installation index {d[0]}")


register.snmp_section(
    name = "snmp_sysappl",
    detect = exists(".1.3.6.1.2.1.54.1.1.1.1.3.*"),  # SYSAPPL-MIB::sysApplInstallPkgProductName
    fetch = [
        SNMPTree(
            base = ".1.3.6.1.2.1.54.1",    # SYSAPPL-MIB::sysApplOBJ
            oids = [ OIDEnd(),
                "1.1.1.3",   # SYSAPPL-MIB::sysApplInstallPkgProductName
            ],
        ),
        SNMPTree(
            base = ".1.3.6.1.2.1.54.1.2.1.1",    # SYSAPPL-MIB::sysApplRunEntry
            oids = [ OIDEnd(),
                OIDBytes("2"),  # SYSAPPL-MIB::sysApplRunStarted
                "3",  # SYSAPPL-MIB::sysApplRunCurrentState
            ],
        ),
    ],
    parse_function = parse_snmp_sysappl,
)

register.check_plugin(
    name = "snmp_sysappl",
    service_name = "SysAppl %s",
    check_function = check_snmp_sysappl,
    check_default_parameters = {},
    discovery_function = discover_snmp_sysappl,
    check_ruleset_name = "snmp_sysappl",
)
