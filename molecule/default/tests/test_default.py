import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'


def test_snort_rule(host):
    f = host.file('/etc/snort/rules/local.rules')

    assert f.exists

    rule_pattern = 'alert tcp any any -> any any'
    rule_pattern += ' ( msg:"Attempted DDoS Attack";'
    rule_pattern += ' uricontent:"/ddos_simulation"; classtype:successful-dos;'
    rule_pattern += ' sid:99000010; priority:1; rev:1; )'
    assert f.contains(rule_pattern)
