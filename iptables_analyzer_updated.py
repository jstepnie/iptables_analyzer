# -*- coding: utf-8 -*-

import ipaddress
from enum import Enum, auto
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font

grouping_choice = None
analyzer = None
irrelevant_rules = []

VALID_CHAINS = ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']

VALID_ACTIONS = [
    'ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN', 'QUEUE', 'DNAT', 'SNAT',
    'MASQUERADE', 'REDIRECT', 'MARK', 'ULOG', 'TCPMSS', 'CLUSTERIP', 'TOS',
    'DSCP', 'NOTRACK', 'SECMARK', 'CONNSECMARK', 'CLASSIFY', 'SET', 'NETMAP',
    'CONNMARK', 'CT', 'HL', 'HMARK', 'IDLETIMER', 'LED', 'RATEEST', 'TEE',
    'TPROXY', 'TRACE', 'MIRROR', 'SNAPSHOT', 'SNMP', 'SNPP',
    'SOLITON', 'SYNPROXY', 'TCPOPTSTRIP', 'TTL', 'NFLOG', 'NFQUEUE'
]


class State:
    _states = ["NEW", "ESTABLISHED", "RELATED", "INVALID"]

    def __init__(self, state="ANY"):
        if state.upper() == "ANY":
            self.states = set(self._states)
        else:
            self.states = set(map(str.upper, state.replace(" ", "").split(',')))
            invalid_states = self.states - set(self._states)
            if invalid_states:
                raise ValueError(f"Invalid state(s): {', '.join(invalid_states)}")

    def __eq__(self, other):
        return self.states == other.states

    def superset_of(self, other):
        if "ANY" in self.states:
            return True
        if "ANY" in other.states:
            return self.states == other.states
        return other.states <= self.states

    def subset_of(self, other):
        if "ANY" in other.states:
            return True
        if "ANY" in self.states:
            return self.states == other.states
        return self.states <= other.states

    def overlaps(self, other):
        if "ANY" in self.states or "ANY" in other.states:
            return True
        return not self.states.isdisjoint(other.states)

    def __repr__(self):
        return ",".join(sorted(self.states))

    @classmethod
    def get_state(cls, state_str):
        return cls(state_str)


class RuleDEF(Enum):
    NZ = auto()
    IMP = auto()
    CC = auto()
    EM = auto()
    PD = auto()
    CD = auto()

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class FieldREL(Enum):
    UNEQUAL = 0
    EQUAL = 1
    SUBSET = 2
    SUPERSET = 3

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Anomaly(Enum):
    AOK = auto()
    SHD = auto()
    COR = auto()
    RD1 = auto()
    RD2 = auto()
    GEN = auto()
    IRR = auto()

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Port:
    def __init__(self, port_spec=None):
        self.port_ranges = []
        if port_spec is None or port_spec.upper() == "ANY":
            self.port_ranges.append((0, 65535))
        else:
            self.port_ranges = self.parse_ports(port_spec)

    @staticmethod
    def parse_ports(port_spec):
        ranges = []
        parts = port_spec.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if ':' in part:
                start, end = part.split(':')
                try:
                    start = int(start)
                    end = int(end)
                    if not (0 <= start <= 65535 and 0 <= end <= 65535):
                        raise ValueError
                    if start > end:
                        raise ValueError
                    ranges.append((start, end))
                except ValueError:
                    raise ValueError(f"Invalid port range '{part}'")
            else:
                try:
                    port = int(part)
                    if not (0 <= port <= 65535):
                        raise ValueError
                    ranges.append((port, port))
                except ValueError:
                    raise ValueError(f"Invalid port number '{part}'")
        if not ranges:
            raise ValueError("No valid ports specified.")
        return ranges

    def __eq__(self, other):
        if not isinstance(other, Port):
            return False
        return set(self.port_ranges) == set(other.port_ranges)

    def superset_of(self, other):
        if self.port_ranges == [(0, 65535)]:
            return True
        if other.port_ranges == [(0, 65535)]:
            return self.port_ranges == other.port_ranges
        for o_start, o_end in other.port_ranges:
            if not any(s_start <= o_start and s_end >= o_end for s_start, s_end in self.port_ranges):
                return False
        return True

    def subset_of(self, other):
        if other.port_ranges == [(0, 65535)]:
            return True
        if self.port_ranges == [(0, 65535)]:
            return self.port_ranges == other.port_ranges
        for s_start, s_end in self.port_ranges:
            if not any(o_start <= s_start and o_end >= s_end for o_start, o_end in other.port_ranges):
                return False
        return True

    def overlaps(self, other):
        for s_start, s_end in self.port_ranges:
            for o_start, o_end in other.port_ranges:
                if s_start <= o_end and o_start <= s_end:
                    return True
        return False

    def __repr__(self):
        parts = []
        for start, end in sorted(self.port_ranges):
            if start == 0 and end == 65535:
                return "ANY"
            if start == end:
                parts.append(str(start))
            else:
                parts.append(f"{start}:{end}")
        return ",".join(parts)

    @classmethod
    def get_port(cls, port_spec):
        if isinstance(port_spec, str) and port_spec.strip().upper() == "ANY":
            return cls()
        try:
            return cls(port_spec.strip())
        except ValueError as ve:
            raise ValueError(f"Invalid port specification '{port_spec}': {ve}")


class Protocol:
    _protocols = [
        "ICMP", "IGMP", "GGP", "IPENCAP", "ST", "TCP", "EGP", "IGP", "BBN-RCC",
        "NVP-II", "PUP", "UDP", "HMP", "XNS-IDP", "RDP", "ISO-TP4", "NETBIOS-NS",
        "NETBIOS-DGM", "NETBIOS-SSN", "ESP", "AH", "EIGRP", "OSPF", "IPV6",
        "GRE", "IP-IN-IP", "IPV6-ICMP", "IPV6-NONXT", "IPV6-OPTS", "RSVP",
        "SCTP", "DCCP", "UDPLITE", "ICMPV6", "ALL", "ANY", "HOPOPT",
    ]

    def __init__(self, protocol):
        self.protocol = protocol.upper()

    def __eq__(self, other):
        return self.protocol == other.protocol

    def superset_of(self, other):
        if self.protocol in ["ANY", "ALL"]:
            return True
        if other.protocol in ["ANY", "ALL"]:
            return self.protocol == other.protocol
        return self.protocol == other.protocol

    def subset_of(self, other):
        if other.protocol in ["ANY", "ALL"]:
            return True
        if self.protocol in ["ANY", "ALL"]:
            return self.protocol == other.protocol
        return self.protocol == other.protocol

    def overlaps(self, other):
        if self.protocol in ["ANY", "ALL"] or other.protocol in ["ANY", "ALL"]:
            return True
        return self.protocol == other.protocol

    def __repr__(self):
        return self.protocol

    @classmethod
    def get_protocol(cls, protocol):
        protocol = protocol.upper()
        if protocol in ["ANY", "ALL"]:
            return cls("ANY")
        if protocol not in cls._protocols:
            raise ValueError(f"Not a recognized protocol '{protocol}'")
        return cls(protocol)

    @classmethod
    def is_valid_protocol(cls, protocol):
        return protocol.upper() in cls._protocols or protocol.upper() in ["ANY", "ALL"]


class Address:
    def __init__(self, address):
        self.network = ipaddress.ip_network(address, strict=False)

    def __eq__(self, other):
        return self.network == other.network

    def superset_of(self, other):
        if self.network == ipaddress.IPv4Network('0.0.0.0/0'):
            return True
        if other.network == ipaddress.IPv4Network('0.0.0.0/0'):
            return self.network == other.network
        return other.network.subnet_of(self.network)

    def subset_of(self, other):
        if other.network == ipaddress.IPv4Network('0.0.0.0/0'):
            return True
        if self.network == ipaddress.IPv4Network('0.0.0.0/0'):
            return self.network == other.network
        return self.network.subnet_of(other.network)

    def overlaps(self, other):
        return self.network.overlaps(other.network)

    def __repr__(self):
        return str(self.network)

    @classmethod
    def get_address(cls, address):
        if address.upper() == "ANY":
            address = "0.0.0.0/0"
        return cls(address)


class Interface:
    def __init__(self, interface):
        self.interface = interface.strip()

    def __eq__(self, other):
        return self.interface == other.interface

    def superset_of(self, other):
        if self.interface.upper() == "ANY":
            return True
        if other.interface.upper() == "ANY":
            return self.interface.upper() == "ANY"
        return self.interface == other.interface

    def subset_of(self, other):
        if other.interface.upper() == "ANY":
            return True
        if self.interface.upper() == "ANY":
            return other.interface.upper() == "ANY"
        return self.interface == other.interface

    def overlaps(self, other):
        if self.interface.upper() == "ANY" or other.interface.upper() == "ANY":
            return True
        return self.interface == other.interface

    def __repr__(self):
        return self.interface


class TcpFlags:
    valid_flags = {"URG", "ACK", "PSH", "RST", "SYN", "FIN", "ALL", "NONE"}

    def __init__(self, flags="ANY"):
        self.flags_str = flags.strip().upper() if flags.strip() else "ANY"
        if self.flags_str != "ANY":
            self.mask, self.comp = self.parse_flags(self.flags_str)
        else:
            self.mask = self.comp = None

    @classmethod
    def parse_flags(cls, flags_str):
        parts = flags_str.strip().split()
        if len(parts) != 2:
            raise ValueError("Invalid TCP flags format. Expected '--tcp-flags [mask] [comp]'")
        mask_flags = set(parts[0].split(','))
        comp_flags = set(parts[1].split(','))
        if not mask_flags.issubset(cls.valid_flags):
            raise ValueError(f"Invalid TCP flags in mask: {mask_flags}")
        if not comp_flags.issubset(cls.valid_flags):
            raise ValueError(f"Invalid TCP flags in comp: {comp_flags}")
        return mask_flags, comp_flags

    def __eq__(self, other):
        return self.flags_str == other.flags_str

    def superset_of(self, other):
        if self.flags_str == "ANY":
            return True
        if other.flags_str == "ANY":
            return self.flags_str == other.flags_str
        if not self.mask and not self.comp:
            return True
        if not other.mask and not other.comp:
            return self.mask == other.mask and self.comp == other.comp
        return self.mask == other.mask and self.comp == other.comp

    def subset_of(self, other):
        if other.flags_str == "ANY":
            return True
        if self.flags_str == "ANY":
            return self.flags_str == other.flags_str
        if not other.mask and not other.comp:
            return False
        return self.mask == other.mask and self.comp == other.comp

    def overlaps(self, other):
        if self.flags_str == "ANY" or other.flags_str == "ANY":
            return True
        if self.mask != other.mask:
            return False
        return not self.comp.isdisjoint(other.comp)

    def __repr__(self):
        return self.flags_str

    @classmethod
    def get_flags(cls, flags):
        if flags.strip() == "":
            return cls("ANY")
        return cls(flags)


class MacAddress:
    def __init__(self, mac="ANY"):
        self.mac = mac.strip().lower() if mac.strip() else "ANY"

    def __eq__(self, other):
        return self.mac == other.mac

    def superset_of(self, other):
        if self.mac.upper() == "ANY":
            return True
        if other.mac.upper() == "ANY":
            return self.mac.upper() == "ANY"
        return self.mac == other.mac

    def subset_of(self, other):
        if other.mac.upper() == "ANY":
            return True
        if self.mac.upper() == "ANY":
            return other.mac.upper() == "ANY"
        return self.mac == other.mac

    def overlaps(self, other):
        if self.mac.upper() == "ANY" or other.mac.upper() == "ANY":
            return True
        return self.mac == other.mac

    def __repr__(self):
        return self.mac

    @classmethod
    def get_mac(cls, mac):
        if mac.strip() == "":
            return cls("ANY")
        return cls(mac)


class Owner:
    def __init__(self, owner="ANY"):
        self.owner = owner.strip() if owner.strip() else "ANY"

    def __eq__(self, other):
        return self.owner == other.owner

    def superset_of(self, other):
        if self.owner.upper() == "ANY":
            return True
        if other.owner.upper() == "ANY":
            return self.owner.upper() == "ANY"
        return self.owner == other.owner

    def subset_of(self, other):
        if other.owner.upper() == "ANY":
            return True
        if self.owner.upper() == "ANY":
            return other.owner.upper() == "ANY"
        return self.owner == other.owner

    def overlaps(self, other):
        if self.owner.upper() == "ANY" or other.owner.upper() == "ANY":
            return True
        return self.owner == other.owner

    def __repr__(self):
        return self.owner

    @classmethod
    def get_owner(cls, owner):
        if owner.strip() == "":
            return cls("ANY")
        return cls(owner)


class Limit:
    def __init__(self, limit="ANY"):
        self.limit = limit.strip() if limit.strip() else "ANY"

    def __eq__(self, other):
        return self.limit == other.limit

    def superset_of(self, other):
        if self.limit.upper() == "ANY":
            return True
        if other.limit.upper() == "ANY":
            return self.limit.upper() == "ANY"
        return self.limit == other.limit

    def subset_of(self, other):
        if other.limit.upper() == "ANY":
            return True
        if self.limit.upper() == "ANY":
            return other.limit.upper() == "ANY"
        return self.limit == other.limit

    def overlaps(self, other):
        return True  

    def __repr__(self):
        return self.limit

    @classmethod
    def get_limit(cls, limit):
        if limit.strip() == "":
            return cls("ANY")
        return cls(limit)


class Packet:
    def __init__(self, protocol, src, s_port, dst, d_port):
        self.fields = {
            "protocol": Protocol.get_protocol(protocol.strip()),
            "src": Address.get_address(src.strip()),
            "sport": Port.get_port(s_port.strip()),
            "dst": Address.get_address(dst.strip()),
            "dport": Port.get_port(d_port.strip()),
        }

    def __eq__(self, other):
        return all(self.fields[key] == other.fields[key] for key in self.fields)

    def __repr__(self):
        return ",".join(map(str, self.fields.values()))


class Policy(Packet):
    def __init__(
        self, chain, protocol, src, s_port, dst, d_port, action, state="ANY",
        in_interface="ANY", out_interface="ANY", tcp_flags="ANY", mac="ANY",
        owner="ANY", limit="ANY"
    ):
        super().__init__(protocol, src, s_port, dst, d_port)
        self.chain = chain
        self.state = State.get_state(state)
        self.action = action
        self.in_interface = Interface(in_interface)
        self.out_interface = Interface(out_interface)
        self.tcp_flags = TcpFlags.get_flags(tcp_flags)
        self.mac = MacAddress.get_mac(mac)
        self.owner = Owner.get_owner(owner)
        self.limit = Limit.get_limit(limit)

    def __eq__(self, other):
        return all(
            self.fields[key] == other.fields[key] for key in self.fields
        ) and self.state == other.state \
            and self.in_interface == other.in_interface \
            and self.out_interface == other.out_interface \
            and self.tcp_flags == other.tcp_flags \
            and self.mac == other.mac \
            and self.owner == other.owner \
            and self.limit == other.limit

    def is_subset_of(self, other):
        return all(
            self.fields[key].subset_of(other.fields[key]) for key in self.fields
        ) and self.state.subset_of(other.state) \
            and self.in_interface.subset_of(other.in_interface) \
            and self.out_interface.subset_of(other.out_interface) \
            and self.tcp_flags.subset_of(other.tcp_flags) \
            and self.mac.subset_of(other.mac) \
            and self.owner.subset_of(other.owner) \
            and self.limit.subset_of(other.limit)

    def is_superset_of(self, other):
        return all(
            self.fields[key].superset_of(other.fields[key]) for key in self.fields
        ) and self.state.superset_of(other.state) \
            and self.in_interface.superset_of(other.in_interface) \
            and self.out_interface.superset_of(other.out_interface) \
            and self.tcp_flags.superset_of(other.tcp_flags) \
            and self.mac.superset_of(other.mac) \
            and self.owner.superset_of(other.owner) \
            and self.limit.superset_of(other.limit)

    def rules_overlap(self, other):
        if self.chain != other.chain:
            return False
        return all(
            self.fields[key].overlaps(other.fields[key]) for key in self.fields
        ) and self.state.overlaps(other.state) \
            and self.in_interface.overlaps(other.in_interface) \
            and self.out_interface.overlaps(other.out_interface) \
            and self.tcp_flags.overlaps(other.tcp_flags) \
            and self.mac.overlaps(other.mac) \
            and self.owner.overlaps(other.owner) \
            and self.limit.overlaps(other.limit)

    def get_rule_relation(self, other):
        if not self.rules_overlap(other):
            return RuleDEF.PD
        if self == other:
            return RuleDEF.EM
        elif self.is_superset_of(other):
            return RuleDEF.IMP
        elif self.is_subset_of(other):
            return RuleDEF.NZ
        else:
            return RuleDEF.CC

    def compare_actions(self, other):
        return self.action == other.action

    def is_match(self, packet):
        return all(
            self.fields[key].superset_of(packet.fields[key]) for key in self.fields
        ) and self.state.superset_of(packet.state) \
            and self.in_interface.superset_of(packet.in_interface) \
            and self.out_interface.superset_of(packet.out_interface)

    def get_action(self):
        return self.action

    def __repr__(self):
        return f"{self.chain},{','.join(map(str, self.fields.values()))},{self.action}"


class PolicyAnalyzer:
    anomaly = {
        (RuleDEF.NZ, False): Anomaly.GEN,
        (RuleDEF.IMP, False): Anomaly.SHD,
        (RuleDEF.EM, False): Anomaly.SHD,
        (RuleDEF.CC, False): Anomaly.COR,
        (RuleDEF.CC, True): Anomaly.AOK,
        (RuleDEF.PD, False): Anomaly.AOK,
        (RuleDEF.PD, True): Anomaly.AOK,
        (RuleDEF.CD, False): Anomaly.AOK,
        (RuleDEF.CD, True): Anomaly.AOK,
        (RuleDEF.IMP, True): Anomaly.RD1,
        (RuleDEF.EM, True): Anomaly.RD1,
        (RuleDEF.NZ, True): Anomaly.RD2,
    }

    def __init__(self, policies):
        self.policies = policies
        self.irrelevant_rules = []

    def add_irrelevant_rule(self, rule, error_message=""):
        self.irrelevant_rules.append((rule, error_message))

    def _get_anomaly(self, rule_relation, same_action):
        return self.anomaly.get((rule_relation, same_action), Anomaly.AOK)

    def get_relations(self):
        rule_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_relations[y] = []
            for x, x_policy in enumerate(self.policies[:y]):
                if y_policy.chain == x_policy.chain:
                    relation = x_policy.get_rule_relation(y_policy)
                    rule_relations[y].append((x, relation))
        return rule_relations

    def get_a_relations(self):
        rule_a_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_a_relations[y] = []
            for x, x_policy in enumerate(self.policies[:y]):
                if y_policy.chain == x_policy.chain:
                    same_action = x_policy.compare_actions(y_policy)
                    rule_a_relations[y].append(same_action)
        return rule_a_relations

    def get_anomalies(self):
        anomalies = {}
        rule_relations = self.get_relations()
        a_relations = self.get_a_relations()

        for ry, ry_relations in rule_relations.items():
            for idx, (rx, relation) in enumerate(ry_relations):
                same_action = a_relations[ry][idx]
                anomaly = self._get_anomaly(relation, same_action)
                if anomaly is not Anomaly.AOK:
                    anomalies.setdefault((rx, ry), []).append(anomaly)

        if self.irrelevant_rules:
            anomalies["IRR"] = [(rule, Anomaly.IRR) for rule, _ in self.irrelevant_rules]

        return anomalies

    def get_first_match(self, packet):
        for i, policy in enumerate(self.policies):
            if policy.is_match(packet):
                return i, policy
        return None


parsed_rules = ([], [])


def analyze_rules(rules):
    global analyzer

    policies = []
    analyzer = PolicyAnalyzer(policies)

    for rule in rules:
        if rule.get('default_policy', False):
            continue
        try:
            protocol = rule.get("protocol", "ANY").upper()
            if protocol == "ALL":
                protocol = "ANY"
            policy = Policy(
                chain=rule["chain"],
                protocol=protocol,
                src=rule.get("source", "ANY"),
                s_port=rule.get("sport", "ANY"),
                dst=rule.get("destination", "ANY"),
                d_port=rule.get("dport", "ANY"),
                action=rule["action"],
                state=rule.get("state", "ANY"),
                in_interface=rule.get("in_interface", "ANY"),
                out_interface=rule.get("out_interface", "ANY"),
                tcp_flags=rule.get("tcp_flags", "ANY"),
                mac=rule.get("mac", "ANY"),
                owner=rule.get("owner", "ANY"),
                limit=rule.get("limit", "ANY"),
            )
            policies.append(policy)
        except Exception as e:
            analyzer.add_irrelevant_rule(rule, str(e))

    anomalies = analyzer.get_anomalies()
    return anomalies


def parse_iptables_rules_v2(rules_text):
    rules = []
    incomplete_rules = []
    for line in rules_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if line.startswith("Chain"):
            continue
        tokens = line.split()
        i = 0
        rule = {}
        rule_added = False
        negation_found = False
        try:
            while i < len(tokens):
                token = tokens[i]
                if token == '!':
                    negation_found = True
                    i += 1
                    continue
                if negation_found:
                    incomplete_rules.append({"rule": line, "missing": "Negation is not supported."})
                    break
                if token == '-A':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing chain name after -A")
                    chain = tokens[i + 1]
                    if chain not in VALID_CHAINS:
                        raise ValueError(f"Invalid chain name '{chain}'")
                    rule['chain'] = chain
                    i += 2
                elif token == '-P':
                    if i + 2 >= len(tokens):
                        raise ValueError("Incomplete default policy rule")
                    chain = tokens[i + 1]
                    action = tokens[i + 2]
                    if chain not in VALID_CHAINS:
                        raise ValueError(f"Invalid chain name '{chain}'")
                    if action.upper() not in VALID_ACTIONS:
                        raise ValueError(f"Invalid action '{action}'")
                    rule['chain'] = chain
                    rule['action'] = action
                    rule['default_policy'] = True
                    i += 3
                    rule.setdefault('protocol', 'ANY')
                    rule.setdefault('source', 'ANY')
                    rule.setdefault('destination', 'ANY')
                    rule.setdefault('sport', 'ANY')
                    rule.setdefault('dport', 'ANY')
                    rule.setdefault('state', 'ANY')
                    rule.setdefault('in_interface', 'ANY')
                    rule.setdefault('out_interface', 'ANY')
                    rule.setdefault('tcp_flags', 'ANY')
                    rule.setdefault('mac', 'ANY')
                    rule.setdefault('owner', 'ANY')
                    rule.setdefault('limit', 'ANY')
                    if not rule_added:
                        rules.append(rule)
                        rule_added = True
                    break
                elif token == '-p':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing protocol after -p")
                    protocol = tokens[i + 1]
                    if not Protocol.is_valid_protocol(protocol):
                        raise ValueError(f"Invalid protocol '{protocol}'")
                    rule['protocol'] = protocol
                    i += 2
                elif token == '-s':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing source address after -s")
                    source = tokens[i + 1]
                    rule['source'] = source
                    i += 2
                elif token == '-d':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing destination address after -d")
                    destination = tokens[i + 1]
                    rule['destination'] = destination
                    i += 2
                elif token == '-i':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing input interface after -i")
                    in_interface = tokens[i + 1]
                    rule['in_interface'] = in_interface
                    i += 2
                elif token == '-o':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing output interface after -o")
                    out_interface = tokens[i + 1]
                    rule['out_interface'] = out_interface
                    i += 2
                elif token == '--dport':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing destination port after --dport")
                    dport = tokens[i + 1]
                    rule['dport'] = dport
                    i += 2
                elif token == '--sport':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing source port after --sport")
                    sport = tokens[i + 1]
                    rule['sport'] = sport
                    i += 2
                elif token == '--tcp-flags':
                    if i + 2 >= len(tokens):
                        raise ValueError("Missing TCP flags after --tcp-flags")
                    tcp_flags = tokens[i + 1] + " " + tokens[i + 2]
                    rule['tcp_flags'] = tcp_flags
                    i += 3
                elif token == '--mac-source':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing MAC address after --mac-source")
                    mac = tokens[i + 1]
                    rule['mac'] = mac
                    i += 2
                elif token in ('--uid-owner', '--gid-owner', '--pid-owner', '--sid-owner'):
                    if i + 1 >= len(tokens):
                        raise ValueError(f"Missing owner value after {token}")
                    owner = tokens[i + 1]
                    rule['owner'] = f"{token} {owner}"
                    i += 2
                elif token == '--limit':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing limit value after --limit")
                    limit = tokens[i + 1]
                    rule['limit'] = limit
                    i += 2
                elif token == '-j':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing action after -j")
                    action = tokens[i + 1]
                    if action.upper() not in VALID_ACTIONS:
                        raise ValueError(f"Invalid action '{action}'")
                    rule['action'] = action
                    i += 2
                elif token == '-m':
                    if i + 1 >= len(tokens):
                        raise ValueError("Missing module name after -m")
                    module = tokens[i + 1]
                    if module == 'state':
                        if i + 3 < len(tokens) and tokens[i + 2] == '--state':
                            state = tokens[i + 3]
                            rule['state'] = state
                            i += 4
                        else:
                            raise ValueError("Incomplete state module usage")
                    elif module == 'conntrack':
                        if i + 3 < len(tokens) and tokens[i + 2] == '--ctstate':
                            state = tokens[i + 3]
                            rule['state'] = state
                            i += 4
                        else:
                            raise ValueError("Incomplete conntrack module usage")
                    elif module == 'mac':
                        i += 2
                    elif module == 'owner':
                        i += 2
                        while i < len(tokens) and tokens[i].startswith('--'):
                            owner_option = tokens[i]
                            if i + 1 >= len(tokens):
                                raise ValueError(f"Missing value after {owner_option}")
                            owner_value = tokens[i + 1]
                            rule['owner'] = f"{owner_option} {owner_value}"
                            i += 2
                    elif module == 'limit':
                        if i + 3 < len(tokens) and tokens[i + 2] == '--limit':
                            limit = tokens[i + 3]
                            rule['limit'] = limit
                            i += 4
                        else:
                            i += 2
                    else:
                        i += 2
                else:
                    i += 1
            rule.setdefault('protocol', 'ANY')
            rule.setdefault('source', 'ANY')
            rule.setdefault('destination', 'ANY')
            rule.setdefault('sport', 'ANY')
            rule.setdefault('dport', 'ANY')
            rule.setdefault('state', 'ANY')
            rule.setdefault('in_interface', 'ANY')
            rule.setdefault('out_interface', 'ANY')
            rule.setdefault('tcp_flags', 'ANY')
            rule.setdefault('mac', 'ANY')
            rule.setdefault('owner', 'ANY')
            rule.setdefault('limit', 'ANY')
            if not rule_added and 'chain' in rule and 'action' in rule:
                rules.append(rule)
                rule_added = True
            elif not rule_added:
                incomplete_rules.append({"rule": line, "missing": "chain or action"})
        except Exception as ve:
            incomplete_rules.append({"rule": line, "missing": str(ve)})
    return rules, incomplete_rules


def format_rule_as_iptables_s(rule):
    if isinstance(rule, tuple):
        rule = {
            'chain': rule[0] if len(rule) > 0 else "N/A",
            'protocol': rule[1] if len(rule) > 1 else "ANY",
            'source': rule[2] if len(rule) > 2 else "ANY",
            'destination': rule[3] if len(rule) > 3 else "ANY",
            'dport': rule[4] if len(rule) > 4 else "ANY",
            'state': rule[5] if len(rule) > 5 else "ANY",
            'action': rule[6] if len(rule) > 6 else "N/A",
            'in_interface': rule[7] if len(rule) > 7 else "ANY",
            'out_interface': rule[8] if len(rule) > 8 else "ANY",
            'tcp_flags': rule[9] if len(rule) > 9 else "ANY",
            'mac': rule[10] if len(rule) > 10 else "ANY",
            'owner': rule[11] if len(rule) > 11 else "ANY",
            'limit': rule[12] if len(rule) > 12 else "ANY",
        }

    chain = rule.get("chain", "N/A")
    protocol = rule.get("protocol", "ANY")
    source = rule.get("source", "ANY")
    destination = rule.get("destination", "ANY")
    dport = rule.get("dport", "ANY")
    sport = rule.get("sport", "ANY")
    state = rule.get("state", "ANY")
    action = rule.get("action", "N/A")
    in_interface = rule.get("in_interface", "ANY")
    out_interface = rule.get("out_interface", "ANY")
    tcp_flags = rule.get("tcp_flags", "ANY")
    mac = rule.get("mac", "ANY")
    owner = rule.get("owner", "ANY")
    limit = rule.get("limit", "ANY")

    parts = []
    if rule.get('default_policy', False):
        parts.append(f"-P {chain} {action}")
    else:
        parts.append(f"-A {chain}")
        if protocol.upper() != "ANY":
            parts.append(f"-p {protocol}")
        if source.upper() != "ANY":
            parts.append(f"-s {source}")
        if destination.upper() != "ANY":
            parts.append(f"-d {destination}")
        if in_interface.upper() != "ANY":
            parts.append(f"-i {in_interface}")
        if out_interface.upper() != "ANY":
            parts.append(f"-o {out_interface}")
        if sport.upper() != "ANY":
            parts.append(f"--sport {sport}")
        if dport.upper() != "ANY":
            parts.append(f"--dport {dport}")
        if tcp_flags.upper() != "ANY":
            parts.append(f"--tcp-flags {tcp_flags}")
        if mac.upper() != "ANY":
            parts.append(f"-m mac --mac-source {mac}")
        if owner.upper() != "ANY":
            parts.append(f"-m owner {owner}")
        if limit.upper() != "ANY":
            parts.append(f"-m limit --limit {limit}")
        if state.upper() != "ANY":
            parts.append(f"-m state --state {state}")
        parts.append(f"-j {action}")
    return " ".join(parts)


def open_file():
    global parsed_rules
    file_path = filedialog.askopenfilename(
        title="Select iptables rules file",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, 'r') as file:
                rules_text = file.read()
                parsed_rules = parse_iptables_rules_v2(rules_text)
                display_parsed_rules(*parsed_rules)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read or parse file: {e}")


def display_parsed_rules(rules, incomplete_rules):
    result_text.delete(1.0, tk.END)

    if rules:
        result_text.insert(tk.END, "Parsed Rules:\n")
        for idx, rule in enumerate(rules, start=1):
            formatted_rule = format_rule_as_iptables_s(rule)
            result_text.insert(tk.END, f"{idx}. {formatted_rule}\n")

    if incomplete_rules:
        result_text.insert(tk.END, "\nIRRELEVANT RULES:\n")
        for incomplete_rule in incomplete_rules:
            result_text.insert(
                tk.END,
                f"Rule: {incomplete_rule['rule']} | Reason: {incomplete_rule['missing']}\n"
            )


def display_grouped_rules():
    for row in rule_table.get_children():
        rule_table.delete(row)

    row_colors = [
        "#1a1a2e", "#16213e", "#0f3460", "#53354a",
        "#903749", "#4b5320", "#8b0000", "#006400",
        "#483d8b", "#8b008b", "#b8860b", "#008b8b",
        "#b22222", "#228b22", "#8b4513", "#2f4f4f"
    ]

    rules, _ = parsed_rules

    group_by = grouping_choice.get()

    rule_id_map.clear()

    if group_by == "None":
        for index, rule in enumerate(rules, start=1):
            if rule.get('default_policy', False):
                color = "#ADD8E6"
            else:
                color = row_colors[(index - 1) % len(row_colors)]
            tag = f"row{index}"
            rule_table.tag_configure(tag, background=color, foreground="green")

            item_id = rule_table.insert(
                "",
                "end",
                values=(
                    index,
                    rule["chain"],
                    rule.get("protocol", "ANY"),
                    rule.get("source", "ANY"),
                    rule.get("destination", "ANY"),
                    rule["action"],
                    rule.get("sport", "ANY"),
                    rule.get("dport", "ANY"),
                    rule.get("in_interface", "ANY"),
                    rule.get("out_interface", "ANY"),
                    rule.get("tcp_flags", "ANY"),
                    rule.get("mac", "ANY"),
                    rule.get("owner", "ANY"),
                    rule.get("limit", "ANY"),
                ),
                tags=(tag,)
            )
            rule_id_map[index - 1] = item_id
    else:
        groups = {}
        for index, rule in enumerate(rules):
            if group_by == "Chain":
                key = rule.get("chain", "ANY")
            elif group_by == "Protocol":
                key = rule.get("protocol", "ANY")
            elif group_by == "Source Port":
                key = rule.get("sport", "ANY")
            elif group_by == "Destination Port":
                key = rule.get("dport", "ANY")
            elif group_by == "Source Address":
                key = rule.get("source", "ANY")
            elif group_by == "Destination Address":
                key = rule.get("destination", "ANY")
            elif group_by == "TCP Flags":
                key = rule.get("tcp_flags", "ANY")
            elif group_by == "MAC":
                key = rule.get("mac", "ANY")
            elif group_by == "Owner":
                key = rule.get("owner", "ANY")
            elif group_by == "Limit":
                key = rule.get("limit", "ANY")
            else:
                key = "ANY"

            groups.setdefault(key, []).append((index, rule))

        color_index = 0
        for key, group_rules in groups.items():
            color = row_colors[color_index % len(row_colors)]
            tag = f"group_{color_index}"
            rule_table.tag_configure(tag, background=color, foreground="green")
            color_index += 1

            for index, rule in group_rules:
                item_id = rule_table.insert(
                    "",
                    "end",
                    values=(
                        index + 1,
                        rule["chain"],
                        rule.get("protocol", "ANY"),
                        rule.get("source", "ANY"),
                        rule.get("destination", "ANY"),
                        rule["action"],
                        rule.get("sport", "ANY"),
                        rule.get("dport", "ANY"),
                        rule.get("in_interface", "ANY"),
                        rule.get("out_interface", "ANY"),
                        rule.get("tcp_flags", "ANY"),
                        rule.get("mac", "ANY"),
                        rule.get("owner", "ANY"),
                        rule.get("limit", "ANY"),
                    ),
                    tags=(tag,)
                )
                rule_id_map[index] = item_id


rule_id_map = {}


def find_anomalies():
    global parsed_rules, rule_table, rule_id_map, irrelevant_rules
    if not parsed_rules:
        messagebox.showwarning("Warning", "No rules loaded. Please load a rules file first.")
        return

    rules, incomplete_rules = parsed_rules

    anomaly_colors = {
        "SHD": ("red", 1, "Shadowing: An earlier rule completely masks a later rule with a different action."),
        "RD1": ("orange", 2, "Redundancy Type 1: An earlier rule is a superset of a later rule with the same action."),
        "RD2": ("#FF69B4", 3, "Redundancy Type 2: An earlier rule is a subset of a later rule with the same action."),
        "GEN": ("yellow", 4, "Generalization: An earlier rule is a subset of a later rule with a different action."),
        "COR": ("purple", 5, "Correlation: Rules overlap but actions differ.")
    }

    policies = []
    irrelevant_rules = []
    for rule in rules:
        if rule.get('default_policy', False):
            continue
        try:
            policy = Policy(
                chain=rule["chain"],
                protocol=rule.get("protocol", "ANY"),
                src=rule.get("source", "ANY"),
                s_port=rule.get("sport", "ANY"),
                dst=rule.get("destination", "ANY"),
                d_port=rule.get("dport", "ANY"),
                action=rule["action"],
                state=rule.get("state", "ANY"),
                in_interface=rule.get("in_interface", "ANY"),
                out_interface=rule.get("out_interface", "ANY"),
                tcp_flags=rule.get("tcp_flags", "ANY"),
                mac=rule.get("mac", "ANY"),
                owner=rule.get("owner", "ANY"),
                limit=rule.get("limit", "ANY"),
            )
            policies.append(policy)
        except Exception as e:
            irrelevant_rules.append((rule, str(e)))

    irrelevant_rules.extend([(rule, "Incomplete: " + rule["missing"]) for rule in incomplete_rules])

    analyzer = PolicyAnalyzer(policies)
    analyzer.irrelevant_rules = irrelevant_rules
    anomalies = analyzer.get_anomalies()

    anomaly_window = tk.Toplevel()
    anomaly_window.title("Anomalies Detected")
    anomaly_window.geometry("800x600")

    bold_font = font.Font(anomaly_window, weight="bold")
    definition_label = tk.Label(
        anomaly_window, text="", wraplength=700, justify="left", bg="black", fg="green", font=bold_font
    )
    definition_label.pack(side=tk.TOP, anchor="w", padx=10, pady=(10, 5))

    filter_frame = tk.Frame(anomaly_window, bg="black")
    filter_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    filter_choice = tk.StringVar(anomaly_window)
    filter_choice.set("All")
    anomaly_types = ["All"] + list(anomaly_colors.keys())
    filter_dropdown = ttk.Combobox(
        filter_frame, textvariable=filter_choice, values=anomaly_types, state="readonly"
    )
    filter_dropdown.pack(side=tk.LEFT, padx=5)

    rule_number_label = tk.Label(filter_frame, text="Rule Number:", bg="black", fg="green")
    rule_number_label.pack(side=tk.LEFT, padx=5)
    rule_number_entry = tk.Entry(filter_frame)
    rule_number_entry.pack(side=tk.LEFT, padx=5)

    filter_button = tk.Button(
        filter_frame, text="Filter",
        command=lambda: filter_anomalies(
            anomaly_text,
            filter_choice.get(),
            anomalies,
            rules,
            anomaly_colors,
            definition_label,
            rule_number_entry.get()
        )
    )
    filter_button.pack(side=tk.LEFT, padx=5)

    anomaly_text = tk.Text(anomaly_window, wrap=tk.WORD, bg="black", fg="green")
    anomaly_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    display_anomalies(anomaly_text, "All", anomalies, rules, anomaly_colors)

    highlighted_rules = apply_highlighting(anomalies, anomaly_colors)
    for rule_index, (color, _) in highlighted_rules.items():
        if rule_index in rule_id_map:
            item_id = rule_id_map[rule_index]
            rule_table.tag_configure(f"color_{color}", foreground=color)
            current_tags = rule_table.item(item_id, "tags")
            rule_table.item(item_id, tags=current_tags + (f"color_{color}",))

    if irrelevant_rules:
        anomaly_text.insert(tk.END, "\nIRRELEVANT RULES:\n", "IRR")
        anomaly_text.tag_configure("IRR", foreground="white")
        for rule, error in irrelevant_rules:
            if 'rule' in rule:
                formatted_rule = rule["rule"]
            else:
                formatted_rule = format_rule_as_iptables_s(rule)
            anomaly_text.insert(tk.END, f"Rule: {formatted_rule}\nError: {error}\n\n", "IRR")


def display_anomalies(anomaly_text, filter_type, anomalies, rules, anomaly_colors, rule_number_filter=None):
    anomaly_text.delete(1.0, tk.END)

    for anomaly_type, (color, _, _) in anomaly_colors.items():
        anomaly_text.tag_configure(anomaly_type, foreground=color)
    anomaly_text.tag_configure("IRR", foreground="white")

    if not anomalies:
        anomaly_text.insert(tk.END, "No anomalies found.\n")
        return

    if "IRR" in anomalies:
        for rule, anomaly_type in anomalies["IRR"]:
            if filter_type == "All" or anomaly_type.name == filter_type:
                if 'rule' in rule:
                    formatted_rule = rule["rule"]
                else:
                    formatted_rule = format_rule_as_iptables_s(rule)
                anomaly_text.insert(
                    tk.END,
                    f"Anomaly Type: {anomaly_type.name}\nRule: {formatted_rule}\n\n",
                    "IRR"
                )

    for key, anomaly_list in anomalies.items():
        if key == "IRR":
            continue
        earlier_rule_index, later_rule_index = key

        displayed_rules_indices = [i for i, rule in enumerate(rules) if not rule.get('default_policy', False)]
        if earlier_rule_index >= len(displayed_rules_indices) or later_rule_index >= len(displayed_rules_indices):
            continue
        adjusted_earlier_index = displayed_rules_indices[earlier_rule_index]
        adjusted_later_index = displayed_rules_indices[later_rule_index]

        if rule_number_filter:
            try:
                rule_number_filter_int = int(rule_number_filter)
            except ValueError:
                continue
            if (adjusted_earlier_index + 1 != rule_number_filter_int) and (adjusted_later_index + 1 != rule_number_filter_int):
                continue

        for anomaly_type in anomaly_list:
            if filter_type == "All" or anomaly_type.name == filter_type:
                color = anomaly_colors.get(anomaly_type.name, ("green",))[0]

                anomaly_text.insert(tk.END, f"\nAnomaly Type: {anomaly_type.name}\n", anomaly_type.name)
                anomaly_text.insert(
                    tk.END,
                    f"Rule {adjusted_earlier_index + 1}: {format_rule_as_iptables_s(rules[adjusted_earlier_index])}\n",
                    anomaly_type.name
                )
                anomaly_text.insert(
                    tk.END,
                    f"Rule {adjusted_later_index + 1}: {format_rule_as_iptables_s(rules[adjusted_later_index])}\n\n",
                    anomaly_type.name
                )


def apply_highlighting(anomalies, anomaly_colors):
    highlighted_rules = {}
    for key, anomaly_list in anomalies.items():
        if key == "IRR":
            continue
        earlier_rule_index, later_rule_index = key
        for anomaly_type in anomaly_list:
            color, priority, _ = anomaly_colors.get(anomaly_type.name, ("green", float("inf"), ""))
            for idx in [earlier_rule_index, later_rule_index]:
                if idx not in highlighted_rules or priority < highlighted_rules[idx][1]:
                    highlighted_rules[idx] = (color, priority)
    return highlighted_rules


def filter_anomalies(anomaly_text, filter_type, anomalies, rules, anomaly_colors, definition_label, rule_number_filter=None):
    if filter_type == "All":
        definition_label.config(text="", fg="green")
    else:
        color, _, description = anomaly_colors.get(filter_type, ("green", 0, ""))
        definition_label.config(text=description, fg=color)

    display_anomalies(anomaly_text, filter_type, anomalies, rules, anomaly_colors, rule_number_filter)


def display_irrelevant_rules():
    global irrelevant_rules

    if not irrelevant_rules:
        messagebox.showinfo("Irrelevant Rules", "No irrelevant rules found.")
        return

    irrelevance_window = tk.Toplevel()
    irrelevance_window.title("Irrelevant Rules Detected")
    irrelevance_window.geometry("800x600")

    explanation = (
        "Irrelevance: These rules could not be parsed into a policy due to syntax errors, invalid values, or unsupported features (e.g., negation)."
    )
    label = tk.Label(
        irrelevance_window, text=explanation, wraplength=750, justify="left", fg="white", bg="black"
    )
    label.pack(pady=10, padx=10)

    irrelevance_text = tk.Text(irrelevance_window, wrap=tk.WORD, bg="black", fg="white")
    irrelevance_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    for rule, error in irrelevant_rules:
        if 'rule' in rule:
            formatted_rule = rule["rule"]
        else:
            formatted_rule = format_rule_as_iptables_s(rule)
        irrelevance_text.insert(tk.END, f"Rule: {formatted_rule}\nError: {error}\n\n")


def show_security_tips():
    global parsed_rules
    rules, _ = parsed_rules

    tips_window = tk.Toplevel()
    tips_window.title("Security Tips")
    tips_window.geometry("800x600")

    tips_text = tk.Text(tips_window, wrap=tk.WORD, bg="black", fg="green")
    tips_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    # Definicja pogrubionej czcionki
    bold_font = font.Font(tips_text, weight="bold")

    # Przypisanie pogrubionej czcionki do tagów
    tips_text.tag_configure('warning', foreground='red', font=bold_font)
    tips_text.tag_configure('positive', foreground='light green', font=bold_font)
    tips_text.tag_configure('negative', foreground='red', font=bold_font)
    tips_text.tag_configure('normal', foreground='green', font=bold_font)

    default_policies = [rule for rule in rules if rule.get('default_policy', False)]

    if not default_policies:
        tips_text.insert(tk.END, "No default policies found.\n")
    else:
        for rule in default_policies:
            if rule['action'].upper() == 'ACCEPT':
                tips_text.insert(
                    tk.END,
                    f"Warning: The default policy for chain {rule['chain']} is ACCEPT. It is a risk to have a default policy of ACCEPT.\n",
                    'warning'
                )
            else:
                tips_text.insert(tk.END, f"The default policy for chain {rule['chain']} is {rule['action']}.\n", 'normal')

    best_practices = """
Best Practices for Using Protocols in iptables:

a. Principle of Least Privilege
   Only allow the minimum necessary traffic required for your services to function.

b. Use Connection Tracking
   Leverage iptables' connection tracking to manage stateful connections.

c. Restrict Access to Critical Services
   Protect services like SSH by limiting access to trusted IPs.

d. Regularly Review and Update Rules
   Periodically audit your iptables rules to ensure they align with your current security requirements.

e. Log Suspicious Activity
   Implement logging for dropped or rejected packets to monitor potential threats.

f. Be cautious with unencrypted protocols
   HTTP [unencrypted] traffic is not encrypted; consider using HTTPS instead.
"""
    tips_text.insert(tk.END, best_practices, 'normal')

    has_drop_ssh_rule = False
    has_accept_ssh_rule = False

    for rule in rules:
        if rule.get('action', '').upper() == 'DROP' and \
           rule.get('protocol', '').upper() == 'TCP' and \
           any(port == 22 for start, end in Port.get_port(rule.get('dport', 'ANY')).port_ranges for port in range(start, end + 1)):
            has_drop_ssh_rule = True
        if rule.get('action', '').upper() == 'ACCEPT' and \
           rule.get('protocol', '').upper() == 'TCP' and \
           any(port == 22 for start, end in Port.get_port(rule.get('dport', 'ANY')).port_ranges for port in range(start, end + 1)):
            has_accept_ssh_rule = True

    if has_drop_ssh_rule and not has_accept_ssh_rule:
        tips_text.insert(tk.END, "\nWarning: You have a rule that drops SSH traffic, which might block your remote connection to Linux if there is no other rule that allows this type of traffic.\n", 'warning')

    drop_ssh_rule = "iptables -A INPUT -p tcp --dport 22 -j DROP"
    tips_text.insert(tk.END, "\nExample of a rule that drops SSH traffic:\n", 'normal')
    tips_text.insert(tk.END, f"{drop_ssh_rule}\n", 'negative')

    example_config = """
Example iptables Rules:

# Allow loopback interface traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related incoming connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow established and related outgoing connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow outbound DNS queries (UDP and TCP)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow outbound HTTP [unencrypted] and HTTPS
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH from specific IP
iptables -A INPUT -p tcp -s 203.0.113.5 --dport 22 -j ACCEPT

# Allow incoming HTTP [unencrypted] and HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ICMP (Ping) with rate limiting
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT

# Allow ESP and AH for IPsec
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p ah -j ACCEPT

# Log and drop all other incoming traffic
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP
"""

    tips_text.insert(tk.END, "\n", 'normal')

    example_rules_text = example_config
    example_rules, _ = parse_iptables_rules_v2(example_rules_text)

    user_rules_set = set(format_rule_as_iptables_s(rule) for rule in rules)

    tips_text.insert(tk.END, "\n", 'normal')

    for line in example_config.strip().splitlines():
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#'):
            tips_text.insert(tk.END, f"{line}\n", 'normal')
            continue
        formatted_line = stripped_line
        example_rule = None
        for rule in example_rules:
            formatted_rule = format_rule_as_iptables_s(rule)
            if formatted_rule == stripped_line:
                example_rule = rule
                break
        if example_rule:
            if formatted_line in user_rules_set:
                tips_text.insert(tk.END, f"{line}\n", 'positive')
            else:
                opposite_action = 'ACCEPT' if example_rule['action'].upper() == 'DROP' else 'DROP'
                modified_rule = rule.copy()
                modified_rule['action'] = opposite_action
                formatted_modified_rule = format_rule_as_iptables_s(modified_rule)
                if formatted_modified_rule in user_rules_set:
                    tips_text.insert(tk.END, f"{line}\n", 'negative')
                else:
                    tips_text.insert(tk.END, f"{line}\n", 'normal')
        else:
            tips_text.insert(tk.END, f"{line}\n", 'normal')

    syntax_text = """
Syntax for Removing or Inserting Rules:

- To remove a rule:
  iptables -D [chain] [rule-specification]

- To insert a rule at a specific position:
  iptables -I [chain] [rule-number] [rule-specification]
"""

    tips_text.insert(tk.END, syntax_text, 'normal')


def setup_gui():
    global grouping_choice

    window = tk.Tk()
    window.title("IPTables Rules Analyzer")
    window.geometry("1200x700")

    open_button = tk.Button(window, text="Open iptables Rules File", command=open_file)
    open_button.pack(pady=5)

    grouping_frame = tk.Frame(window)
    grouping_frame.pack(pady=5)

    grouping_label = tk.Label(grouping_frame, text="Group by:")
    grouping_label.pack(side=tk.LEFT, padx=5)

    grouping_choice = tk.StringVar(window)
    grouping_options = [
        "None",
        "Chain",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Source Address",
        "Destination Address",
        "TCP Flags",
        "MAC",
        "Owner",
        "Limit"
    ]

    grouping_dropdown = ttk.Combobox(
        grouping_frame, textvariable=grouping_choice,
        values=grouping_options, state="readonly"
    )
    grouping_dropdown.pack(side=tk.LEFT, padx=5)
    grouping_dropdown.current(0)

    group_button = tk.Button(grouping_frame, text="Group and Display Rules", command=display_grouped_rules)
    group_button.pack(side=tk.LEFT, padx=5)

    buttons_frame = tk.Frame(window)
    buttons_frame.pack(pady=5)

    find_button = tk.Button(buttons_frame, text="Find Anomalies", command=find_anomalies)
    find_button.pack(side=tk.LEFT, padx=5)

    irrelevance_button = tk.Button(buttons_frame, text="Irrelevance", command=display_irrelevant_rules)
    irrelevance_button.pack(side=tk.LEFT, padx=5)

    security_button = tk.Button(buttons_frame, text="Security Tips", bg="light green", command=show_security_tips)
    security_button.pack(side=tk.LEFT, padx=5)

    table_frame = tk.Frame(window, bg="white", padx=2, pady=2)
    table_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    global rule_table
    rule_table = ttk.Treeview(
        table_frame,
        columns=(
            "Number", "Chain", "Protocol", "Source", "Destination", "Action",
            "Sport", "Dport", "In Interface", "Out Interface",
            "TCP Flags", "MAC", "Owner", "Limit"
        ),
        show="headings",
        selectmode="browse",
    )
    rule_table.heading("Number", text="No.")
    rule_table.heading("Chain", text="Chain")
    rule_table.heading("Protocol", text="Protocol")
    rule_table.heading("Source", text="Source")
    rule_table.heading("Destination", text="Destination")
    rule_table.heading("Action", text="Action")
    rule_table.heading("Sport", text="Source Port")
    rule_table.heading("Dport", text="Destination Port")
    rule_table.heading("In Interface", text="In Interface")
    rule_table.heading("Out Interface", text="Out Interface")
    rule_table.heading("TCP Flags", text="TCP Flags")
    rule_table.heading("MAC", text="MAC")
    rule_table.heading("Owner", text="Owner")
    rule_table.heading("Limit", text="Limit")

    rule_table.column("Number", width=50, anchor='center')
    rule_table.column("Chain", width=100, anchor='center')
    rule_table.column("Protocol", width=100, anchor='center')
    rule_table.column("Source", width=150, anchor='center')
    rule_table.column("Destination", width=150, anchor='center')
    rule_table.column("Action", width=100, anchor='center')
    rule_table.column("Sport", width=100, anchor='center')
    rule_table.column("Dport", width=120, anchor='center')
    rule_table.column("In Interface", width=120, anchor='center')
    rule_table.column("Out Interface", width=120, anchor='center')
    rule_table.column("TCP Flags", width=150, anchor='center')
    rule_table.column("MAC", width=150, anchor='center')
    rule_table.column("Owner", width=150, anchor='center')
    rule_table.column("Limit", width=100, anchor='center')

    style = ttk.Style()
    style.configure(
        "Treeview",
        background="black",
        foreground="green",
        fieldbackground="black",
        rowheight=25,
        highlightthickness=1,
        borderwidth=1
    )
    style.configure("Treeview.Heading", background="white", foreground="black", relief="solid")

    rule_table.pack(expand=True, fill=tk.BOTH, padx=1, pady=1)

    global result_text
    result_text = tk.Text(window, wrap=tk.WORD, height=10, bg="black", fg="green")
    result_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    window.mainloop()


if __name__ == "__main__":
    setup_gui()
