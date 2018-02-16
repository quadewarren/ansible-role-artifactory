#!/usr/bin/python
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: artifactory_replication

short_description: Provides management repositoriy replication in JFrog Artifactory

version_added: "2.5"

description:
    - Provides basic management operations for configuration repository
      replication in JFrog Artifactory.

options:
    artifactory_url:
        description:
            - The target URL for managing artifactory. For certain operations,
              you can include the group name appended to the end of the
              url.
        required: true
    name:
        description:
            - Name of the local repository to configure replication against.
        required: true
    replication_config:
        description:
            - The string representations of the JSON used to configure the
              replication for the given repository.
    username:
        description:
            - username to be used in Basic Auth against Artifactory. Not
              required if using auth_token for basic auth.
    auth_password:
        description:
            - password to be used in Basic Auth against Artifactory. Not
              required if using auth_token for basic auth.
    auth_token:
        description:
            - authentication token to be used in Basic Auth against
              Artifactory. Not required if using username/auth_password for
              basic auth.
    validate_certs:
        description:
            - True to validate SSL certificates, False otherwise.
        type: bool
        default: false
    client_cert:
        description:
            - PEM formatted certificate chain file to be used for SSL client
              authentication. This file can also include the key as well, and
              if the key is included, I(client_key) is not required
    client_key:
        description:
            - PEM formatted file that contains your private key to be used for
              SSL client authentication. If I(client_cert) contains both the
              certificate and key, this option is not required.
    force_basic_auth:
        description:
            - The library used by the uri module only sends authentication
              information when a webservice responds to an initial request
              with a 401 status. Since some basic auth services do not properly
              send a 401, logins will fail. This option forces the sending of
              the Basic authentication header upon initial request.
        type: bool
        default: false
    state:
        description:
            - The state the replication configuration should be in.
              'present' ensures that the target exists, but is not replaced.
              The configuration supplied will overwrite the configuration that
              exists. 'absent' ensures that the the target is deleted.
              'read' will return the configuration if the target exists.
        choices:
          - present
          - absent
          - read
        default: read
    replication_config_dict:
        description:
            - A dictionary in yaml format of valid configuration for repository
              replication. These dictionary values must match any other values
              passed in, such as those within top-level parameters or within
              the configuration string in replication_config.
    cronExp:
        description:
            - A cron expression that represents the schedule that push/pull
              replication will take place. This is independent of event based
              replication.
    enableEventReplication:
        description:
            - Enable event based replication whenever a repository is created,
              updated, or deleted..
        type: bool
        default: false
    remote_url:
        description:
            - The url of the target repository to configure push or pull
              replication against.
    replication_username:
        description:
            - The username Artifactory will use to execute push/pull
              replication operations against a remote.
    replication_password:
        description:
            - The password Artifactory will use to execute push/pull
              replication operations against a remote.


author:
    - Kyle Haley (@quadewarren)
'''

EXAMPLES = '''
# Configure replication on an existing repo with cron and event based
# replication configured.
- name: Configure replication for a repository
  artifactory_replication:
    artifactory_url: http://art.url.com/artifactory/api/replications/
    auth_token: MY_TOKEN
    name: bower-local
    cronExp: "0 0 12 * * ?"
    enableEventReplication: true
    replication_username: remote_username
    replication_password: my_password
    remote_url: http://the.remote.repo.com/artifactory/remote-repo
    state: present

# Update the replication configuration, set event based replication to false
- name: Update the replication configuration for a repository
  artifactory_replication:
    artifactory_url: http://art.url.com/artifactory/api/replications/
    auth_token: MY_TOKEN
    name: bower-local
    enableEventReplication: false
    state: present

- name: delete the replication configuration
  artifactory_replication:
    artifactory_url: http://art.url.com/artifactory/api/replications/
    auth_token: MY_TOKEN
    name: bower-local
    state: absent
'''

RETURN = '''
original_message:
    description:
        - A brief sentence describing what action the module was attempting
          to make against the replication configuration and what
          artifactory url.
    returned: success
    type: str
message:
    description: The result of the attempted action.
    returned: success
    type: str
config:
    description:
        - The configuration of a successfully created replication config,
          an updated replication config (whether or not changed=True), or
          the config of a replication config that was successfully deleted.
    returned: success
    type: dict
'''
import ast
import json

import ansible.module_utils.artifactory as art_base

from ansible.module_utils.basic import AnsibleModule


REPLICATION_CONFIG_MAP = {
    "name":
        {"always_required": True},
    "remote_url":
        {"always_required": True}}
URI_CONFIG_MAP = {"api/replications": REPLICATION_CONFIG_MAP}


def main():
    state_map = ['present', 'absent', 'read', 'list']
    module_args = dict(
        artifactory_url=dict(type='str', required=True),
        name=dict(type='str', required=True),
        replication_config=dict(type='str', default=None),
        username=dict(type='str', default=None),
        auth_password=dict(type='str', no_log=True, default=None),
        auth_token=dict(type='str', no_log=True, default=None),
        validate_certs=dict(type='bool', default=False),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        force_basic_auth=dict(type='bool', default=False),
        state=dict(type='str', default='read', choices=state_map),
        replication_config_dict=dict(type='dict', default=dict()),
        remote_url=dict(type='str', default=None),
        replication_username=dict(type='str', default=None),
        replication_password=dict(type='str', default=None),
        cronExp=dict(type='str', default=None),
        enableEventReplication=dict(type='str', default=None),
    )

    result = dict(
        changed=False,
        original_message='',
        message='',
        config=dict()
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[['username', 'auth_password']],
        required_one_of=[['auth_password', 'auth_token']],
        mutually_exclusive=[['auth_password', 'auth_token']],
        required_if=[['state', 'present',
                      ['artifactory_url', 'name',
                       'remote_url', 'replication_username',
                       'replication_password']],
                     ['state', 'absent', ['artifactory_url', 'name']],
                     ['state', 'read', ['artifactory_url', 'name']]],
        supports_check_mode=True,
    )

    artifactory_url = module.params['artifactory_url']
    name = module.params['name']
    replication_config = module.params['replication_config']
    username = module.params['username']
    auth_password = module.params['auth_password']
    auth_token = module.params['auth_token']
    validate_certs = module.params['validate_certs']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    force_basic_auth = module.params['force_basic_auth']
    state = module.params['state']
    replication_config_dict = module.params['replication_config_dict']

    if replication_config:
        # temporarily convert to dict for validation
        replication_config = ast.literal_eval(replication_config)

    fail_messages = []

    fails = art_base.validate_config_params(replication_config,
                                            replication_config_dict,
                                            'replication_config',
                                            'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('name', module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('remote_url', module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('replication_username', module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('replication_password', module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('cronExp', module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('enableEventReplication',
                                               module,
                                               replication_config,
                                               replication_config_dict,
                                               'replication_config',
                                               'replication_config_dict')
    fail_messages.extend(fails)

    # Populate failure messages
    failure_message = "".join(fail_messages)

    # Conflicting config values should not be resolved
    if failure_message:
        module.fail_json(msg=failure_message, **result)

    sec_dict = dict()
    if module.params['name']:
        sec_dict['name'] = module.params['name']
    if module.params['remote_url']:
        sec_dict['remote_url'] = module.params['remote_url']
    if module.params['email']:
        sec_dict['email'] = module.params['email']
    if module.params['replication_username']:
        sec_dict['replication_username'] =\
                module.params['replication_username']
    if module.params['replication_password']:
        sec_dict['replication_password'] =\
                module.params['replication_password']
    if module.params['cronExp']:
        sec_dict['cronExp'] = module.params['cronExp']
    if module.params['enableEventReplication']:
        sec_dict['enableEventReplication'] =\
                module.params['enableEventReplication']
    if replication_config:
        sec_dict.update(replication_config)
    if replication_config_dict:
        sec_dict.update(replication_config_dict)
    replication_config = json.dumps(sec_dict)

    result['original_message'] = ("Perform state '%s' against target '%s' "
                                  "within artifactory '%s'"
                                  % (state, name, artifactory_url))

    art_replication = art_base.ArtifactoryBase(
        artifactory_url=artifactory_url,
        name=name,
        art_config=replication_config,
        username=username,
        password=auth_password,
        auth_token=auth_token,
        validate_certs=validate_certs,
        client_cert=client_cert,
        client_key=client_key,
        force_basic_auth=force_basic_auth,
        config_map=URI_CONFIG_MAP)
    art_base.run_module(module, art_replication, "Repository replication",
                        result, fail_messages, replication_config)


if __name__ == "__main__":
    main()
