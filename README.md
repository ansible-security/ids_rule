ids_rule
===========

# Tech Preview

A role to manage rules and signatures for many different Intrusion Detection
Systems, these are defined as "providers" to the Role.

Current supported list of providers:
* snort

Requirements
------------

Red Hat Enterprise Linux 7.x, or derived Linux distribution such as CentOS 7,
Scientific Linux 7, etc

* [idstools](https://idstools.readthedocs.io/en/latest/)

Role Variables
--------------

* `ids_provider` - This defines what IDS provider (Default Value: "snort")
* `ids_rule` - The rule you would like to add or remove to/from managed set of
   rules
* `ids_rule_state` - Should be one of `present` or `absent`
* `ids_rules_file` - The rules file the manage (default:
  `/etc/snort/rules/local.rules`)

Dependencies
------------

Dependencies will vary by provider

## snort Dependencies

* [


Example Playbook
----------------

    - name: manage snort rules
      hosts: idshosts
      become: yes
      become_user: root
      gather_facts: false

      vars:
        ids_provider: snort
        protocol: tcp
        source_port: any
        source_ip: any
        dest_port: any
        dest_ip: any

      tasks:
        - name: Add snort password attack rule
          include_role:
            name: "ids_rule"
          vars:
            ids_rule: 'alert {{protocol}} {{source_ip}} {{source_port}} -> {{dest_ip}} {{dest_port}}  (msg:"Attempted /etc/passwd Attack"; uricontent:"/etc/passwd"; classtype:attempted-user; sid:99000004; priority:1; rev:1;)'
            ids_rules_file: '/etc/snort/rules/local.rules'
            ids_rule_state: present


License
-------

GPLv3

Author Information
------------------

[Ansible Security Automation Team](https://github.com/ansible-security)
