ids_rule
===========

# This content is currently under development and should not be considered production ready

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
* `ids_install_normalize_logs` - Set to True to setup log normalization
  (Default Value: True)

## snort

For the Snort provider you will need to set the `ids_provider` variable
as such:

    vars:
      ids_provider: snort

When `ids_install_normalize_logs` is set, the role will also install
[barnyard2](https://github.com/firnsy/barnyard2) in service of normalizing the
snort logs.

All other `ids_install_*` variables will be namespaced to the specific provider.

### snort variables

* `ids_provider` - Default value: `"snort"`
* `ids_install_snort_interface` - Default value: `eth0`
* `ids_install_snort_version` - Default value: `2.9.12`
* `ids_install_snort_daq_version` - Default value: `2.0.6`
* `ids_install_snort_rulesversion` - Default value: `29120`
* `ids_install_snort_promiscuous_interface` - Default value: `False`
* `ids_install_snort_logdir` - Default value: `"/var/log/snort"`
* `ids_install_snort_logfile` - Default value: `"snort.log"`
* `ids_install_snort_config_path` - Default value: `"/etc/snort/snort.conf"`


Dependencies
------------

* `geerlingguy.repo-epel`


Example Playbook
----------------

    - name: configure snort
      hosts: idshosts
      vars:
          ids_provider: "snort"
          ids_install_normalize_logs: True
      tasks:
        - name: import ids_install role
          import_role:
            name: "ids_install"

License
-------

BSD

Author Information
------------------

[Ansible Security Automation Team](https://github.com/ansible-security)
