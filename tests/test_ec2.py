from scanner.checks.ec2 import open_admin_ports, open_db_ports, unencrypted_volumes
from tests.conftest import make_security_group, make_volume

ANYWHERE = "0.0.0.0/0"


def flagged(check, aws):
    """Findings keyed by group id (resource is 'sg-... (name)')."""
    return {resource.split()[0]: detail for resource, detail in check(aws)}


# --- EC2.1 SSH / RDP ----------------------------------------------------------


def test_ssh_open_to_world_is_flagged(aws):
    sg = make_security_group(aws, "ssh-world", ("tcp", 22, 22, ANYWHERE))
    assert flagged(open_admin_ports, aws) == {sg: "open to the internet on 22 (SSH)"}


def test_rdp_open_to_ipv6_world_is_flagged(aws):
    sg = make_security_group(aws, "rdp-v6", ("tcp", 3389, 3389, "::/0"))
    assert flagged(open_admin_ports, aws) == {sg: "open to the internet on 3389 (RDP)"}


def test_port_range_covering_ssh_is_flagged(aws):
    sg = make_security_group(aws, "wide-range", ("tcp", 20, 25, ANYWHERE))
    assert set(flagged(open_admin_ports, aws)) == {sg}


def test_all_traffic_rule_is_flagged_for_every_port(aws):
    sg = make_security_group(aws, "allow-all", ("-1", -1, -1, ANYWHERE))
    assert flagged(open_admin_ports, aws)[sg] == "open to the internet on 22 (SSH), 3389 (RDP)"
    assert "3306 (MySQL)" in flagged(open_db_ports, aws)[sg]


def test_ssh_from_office_range_is_not_flagged(aws):
    make_security_group(aws, "ssh-office", ("tcp", 22, 22, "203.0.113.0/24"))
    assert flagged(open_admin_ports, aws) == {}


def test_world_open_web_ports_are_not_flagged(aws):
    make_security_group(aws, "web", ("tcp", 80, 80, ANYWHERE), ("tcp", 443, 443, ANYWHERE))
    assert flagged(open_admin_ports, aws) == {}
    assert flagged(open_db_ports, aws) == {}


def test_icmp_type_numbers_are_not_mistaken_for_ports(aws):
    # ICMP FromPort/ToPort are type/code; a range spanning 22 is not SSH.
    make_security_group(aws, "ping", ("icmp", 0, 255, ANYWHERE))
    assert flagged(open_admin_ports, aws) == {}


def test_default_group_is_not_flagged(aws):
    # moto's default VPC group, like AWS's, has no world-open ingress.
    assert flagged(open_admin_ports, aws) == {}


# --- EC2.2 database ports -----------------------------------------------------


def test_each_db_port_open_to_world_is_flagged(aws):
    for port in (3306, 5432, 1433, 27017, 6379):
        make_security_group(aws, f"db-{port}", ("tcp", port, port, ANYWHERE))
    assert len(flagged(open_db_ports, aws)) == 5


def test_db_port_findings_name_every_exposed_port(aws):
    sg = make_security_group(aws, "two-dbs", ("tcp", 5432, 5432, ANYWHERE), ("tcp", 6379, 6379, "::/0"))
    assert flagged(open_db_ports, aws) == {sg: "open to the internet on 5432 (PostgreSQL), 6379 (Redis)"}


def test_db_port_from_private_range_is_not_flagged(aws):
    make_security_group(aws, "db-internal", ("tcp", 3306, 3306, "10.0.0.0/16"))
    assert flagged(open_db_ports, aws) == {}


def test_ssh_and_db_checks_do_not_overlap(aws):
    ssh = make_security_group(aws, "ssh-only", ("tcp", 22, 22, ANYWHERE))
    db = make_security_group(aws, "db-only", ("tcp", 3306, 3306, ANYWHERE))
    assert set(flagged(open_admin_ports, aws)) == {ssh}
    assert set(flagged(open_db_ports, aws)) == {db}


# --- EC2.3 unencrypted EBS ----------------------------------------------------


def test_unencrypted_volume_is_flagged(aws):
    volume = make_volume(aws)
    assert dict(unencrypted_volumes(aws)) == {volume: "1 GiB volume, available, unencrypted"}


def test_encrypted_volume_is_not_flagged(aws):
    make_volume(aws, encrypted=True)
    assert dict(unencrypted_volumes(aws)) == {}
