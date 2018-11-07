#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Adam Miller (admiller@redhat.com)
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: snort_rule
short_description: Manage snort rules
description:
  - This module allows for addition or deletion of snort rules
version_added: "2.7"
options:
  rule:
    description:
      - "The rule definition"
    required: true
  state:
    description:
      - Add or remove a rule.
    required: true
    choices: [ "present", "absent" ]
  rules_file:
    description:
      - Path to the .rules file this rule should exist in
      required: false
      default: /etc/snort/rules/ansible_managed.rules
requirements: [ 'idstools>= 0.6.3' ]
author: "Adam Miller (@maxamillion)"
'''

EXAMPLES = '''
- snort_rule:
    rule: 'alert tcp {{home_net}} any -> {{external_net}} {{http_ports}} (msg:"APP-DETECT Absolute Software Computrace outbound connection - search.namequery.com"; flow:to_server,established; content:"Host|3A| search.namequery.com|0D 0A|"; fast_pattern:only; http_header; content:"TagId: "; http_header; metadata:policy security-ips drop, ruleset community, service http; reference:url,absolute.com/support/consumer/technology_computrace; reference:url,www.blackhat.com/presentations/bh-usa-09/ORTEGA/BHUSA09-Ortega-DeactivateRootkit-PAPER.pdf; classtype:misc-activity; sid:26287; rev:4;)'
    state: present

- snort_rule:
    rule: 'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any'
    state: present
    rules_file: /etc/snort/rules/grab_everything_http.rules
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

HAS_IDSTOOLS = True
try:
    from idstools import rule
    from idstools import maps
except ImportError:
    HAS_IDSTOOLS = False


SIGMAP_FILE = "/etc/snort/sid-msg.map"
GENMAP_FILE = "/etc/snort/gen-msg.map"

def main():

    module = AnsibleModule(
        argument_spec=dict(
            rule=dict(required=True, default=None),
            state=dict(choices=['present', 'absent'], required=True),
            rules_file=dict(required=False, default='/etc/snort/rules/ansible_managed.rules'),
        ),
        supports_check_mode=True
    )

    if not HAS_IDSTOOLS:
        module.fail_json(msg="Python module idstools not found on host, but is required for snort_rule Ansible module")

    try:
        matched_rules = [
            snort_rule for snort_rule in rule.parse_file(module.params['rules_file'])
            if to_text(snort_rule) == to_text(rule.parse(module.params['rule']))
        ]
    except IOError:
        module.fail_json(msg="rule file {} not found or permission was denied attempting access it".format(module.params['rules_file']))
    rule_found = True if matched_rules else False

    sigmap = maps.SignatureMap()
    try:
        sigmap.load_generator_map(open(GENMAP_FILE, 'r'))
    except IOError:
        module.fail_json(msg="generator file {} not found or permission was denied attempting to access it".format(GENMAP_FILE))
    try:
        sigmap.load_signature_map(open(SIGMAP_FILE, 'r'))
    except IOError:
        module.fail_json(msg="signature file {} not found or permission was denied attempting to access it".format(SIGMAP_FILE))


    if module.params['state'] == 'present' and rule_found:
        module.exit_json(
            msg="Rule '{}' already present in rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=False
        )
    elif module.params['state'] == 'present' and not rule_found:
        if module.check_mode:
            module.exit_json(
                msg="Rule '{}' would be added to rules_file {}".format(module.params['rule'], module.params['rules_file']),
                changed=True
            )

        new_snort_rule = rule.parse(module.params['rule'])

        with open(module.params['rules_file'], 'a') as rules_file:
            rules_file.write(to_text("\n{}".format(new_snort_rule)))

        with open(SIGMAP_FILE, 'a') as sigmap_file:
            if "ref" in new_snort_rule and len(new_snort_rule["ref"]) > 0:
                sigmap_file.write(to_text("\n{} || {} || {}".format(
                    new_snort_rule['sid'], new_snort_rule['msg'], " || ".join(new_snort_rule['ref'])
                )))
            else:
                sigmap_file.write(to_text("\n{} || {}".format(new_snort_rule['sid'], new_snort_rule['msg'])))

        module.exit_json(
            msg="Rule '{}' added to rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=True
        )

    if module.params['state'] == 'absent' and not rule_found:
        module.exit_json(
            msg="Rule '{}' does not exist in rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=False
        )
    elif module.params['state'] == 'absent' and rule_found:
        new_snort_rule = rule.parse(module.params['rule'])

        changed = False

        orig_rulefile_contents = []
        orig_sigmapfile_contents = []
        new_rulefile_contents = []
        new_sigmapfile_contents = []
        with open(module.params['rules_file'], 'r') as rules_file:
            orig_rulefile_contents = rules_file.readlines()
        with open(SIGMAP_FILE,'r') as sigmap_file:
            orig_sigmapfile_contents = sigmap_file.readlines()

        new_rulefile_contents = [
            line for line in orig_rulefile_contents
            if new_snort_rule != rule.parse(line)
        ]

        if "ref" in new_snort_rule and len(new_snort_rule["ref"]) > 0:
            new_sigmapfile_contents = [
                line for line in orig_sigmapfile_contents
                if "{} || {} || {}".format(
                    new_snort_rule['sid'], new_snort_rule['msg'], ' || '.join(new_snort_rule['ref'])
                ) != line.strip()
            ]
        else:
            new_sigmapfile_contents = [
                line for line in orig_sigmapfile_contents
                if "{} || {}".format(new_snort_rule['sid'], new_snort_rule['msg']) != line.strip()
            ]

        if module.check_mode:
            if len(orig_rulefile_contents) != len(new_rulefile_contents):
                module.exit_json(
                    msg="Rule '{}' would have been removed from rules_file {}".format(
                        module.params['rule'],
                        module.params['rules_file']
                    ),
                    changed=True
                )

        if len(orig_rulefile_contents) != len(new_rulefile_contents):
            changed = True
            with open(module.params['rules_file'], 'w') as rules_file:
                for line in new_rulefile_contents:
                    rules_file.write(line)

        if new_sigmapfile_contents and (len(orig_sigmapfile_contents) != len(new_sigmapfile_contents)):
            changed = True
            with open(SIGMAP_FILE, 'w') as sigmap_file:
                for line in new_sigmapfile_contents:
                    sigmap_file.write(line)

        module.exit_json(
            msg="Rule '{}' has been removed from rules_file {}".format(
                module.params['rule'],
                module.params['rules_file']
            ),
            changed=changed
        )


if __name__ == '__main__':
    main()
