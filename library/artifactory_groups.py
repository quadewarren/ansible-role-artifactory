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
module: artifactory_groups

short_description: Provides management operations for security operations in JFrog Artifactory

version_added: "2.5"

description:
    - Provides basic management operations against security groups in JFrog
      Artifactory 5+. Please reference this configuration spec for the creation
      of users, groups, or permission targets.
      U(https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON)

options:
    artifactory_url:
        description:
            - The target URL for managing artifactory. For certain operations,
              you can include the group name appended to the end of the
              url.
        required: true
    name:
        description:
            - Name of the artifactory security group target to perform
              CRUD operations against. WARNING: The UI will enforce lowercase
              when importing LDAP groups, but the API side WILL not. If you are
              creating LDAP groups via the API, you will need to make sure all
              LDAP group names are lowercase since this will impact how
              Artifactory matches. See Artifactory Knowledge Article: 000001563
        required: true
    group_config:
        description:
            - The string representations of the JSON used to create the target
              security group. Please reference the JFrog Artifactory Security
              Configuration JSON for directions on what key/values to use.
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
            - The state the artifactory security group should be in.
              'present' ensures that the target exists, but is not replaced.
              The configuration supplied will overwrite the configuration that
              exists. 'absent' ensures that the the target is deleted.
              'read' will return the configuration if the target exists.
              'list' will return a list of all targets against the specified
              url that currently exist in the target artifactory. If you wish
              to, for instance, append a list of repositories that a permission
              target has access to, you will need to construct the complete
              list outside of the module and pass it in.
        choices:
          - present
          - absent
          - read
          - list
        default: read
    group_config_dict:
        description:
            - A dictionary in yaml format of valid configuration values against
              an artifactory security group. These
              dictionary values must match any other values passed in, such as
              those within top-level parameters or within the configuration
              string in group_config.

author:
    - Kyle Haley (@quadewarren)
'''

EXAMPLES = '''
# Create a security group using top-level parameters
- name: create a new group using config hash
  artifactory_groups:
    artifactory_url: http://art.url.com/artifactory/api/security/groups
    auth_token: MY_TOKEN
    name: "temp-group"
    group_config_dict:
      description: A group representing a collection of users. Can be LDAP.
    state: present

- name: update the group using config hash
  artifactory_groups:
    artifactory_url: http://art.url.com/artifactory/api/security/groups
    auth_token: MY_TOKEN
    name: "temp-group"
    group_config_dict:
      description: A group of users from LDAP. Can be LDAP.
      realm: "Realm name (e.g. ARTIFACTORY, CROWD)"
    state: present

- name: delete the security group
  artifactory_groups:
    artifactory_url: http://art.url.com/artifactory/api/security/groups
    auth_token: MY_TOKEN
    name: "temp-group"
    state: absent
'''

RETURN = '''
original_message:
    description:
        - A brief sentence describing what action the module was attempting
          to take against which artifactory security group and what
          artifactory url.
    returned: success
    type: str
message:
    description: The result of the attempted action.
    returned: success
    type: str
config:
    description:
        - The configuration of a successfully created security group,
          an updated security group (whether or not changed=True), or
          the config of a security group that was successfully deleted.
    returned: success
    type: dict
'''


import ast

import ansible.module_utils.artifactory as art_base

from ansible.module_utils.basic import AnsibleModule


URI_CONFIG_MAP = {"api/security/groups": True}


def main():
    state_map = ['present', 'absent', 'read', 'list']
    module_args = dict(
        artifactory_url=dict(type='str', required=True),
        name=dict(type='str', default=''),
        group_config=dict(type='str', default=None),
        username=dict(type='str', default=None),
        auth_password=dict(type='str', no_log=True, default=None),
        auth_token=dict(type='str', no_log=True, default=None),
        validate_certs=dict(type='bool', default=False),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        force_basic_auth=dict(type='bool', default=False),
        state=dict(type='str', default='read', choices=state_map),
        group_config_dict=dict(type='dict', default=dict()),
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
        required_if=[['state', 'present', ['artifactory_url', 'name']],
                     ['state', 'absent', ['artifactory_url', 'name']],
                     ['state', 'read', ['artifactory_url', 'name']]],
        supports_check_mode=True,
    )

    artifactory_url = module.params['artifactory_url']
    name = module.params['name']
    group_config = module.params['group_config']
    username = module.params['username']
    auth_password = module.params['auth_password']
    auth_token = module.params['auth_token']
    validate_certs = module.params['validate_certs']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    force_basic_auth = module.params['force_basic_auth']
    state = module.params['state']
    group_config_dict = module.params['group_config_dict']

    if group_config:
        # temporarily convert to dict for validation
        group_config = ast.literal_eval(group_config)

    fail_messages = []

    fails = art_base.validate_config_params(group_config, group_config_dict,
                                            'group_config',
                                            'group_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('name', module, group_config,
                                               group_config_dict,
                                               'group_config',
                                               'group_config_dict')
    fail_messages.extend(fails)

    # Populate failure messages
    failure_message = "".join(fail_messages)

    # Conflicting config values should not be resolved
    if failure_message:
        module.fail_json(msg=failure_message, **result)

    sec_dict = dict()
    if module.params['name']:
        sec_dict['name'] = module.params['name']
    if group_config:
        sec_dict.update(group_config)
    if group_config_dict:
        sec_dict.update(group_config_dict)
    # Artifactory stores the group name as lowercase (even if it was passed as
    # multi-case). Calls against that group after it is created will fail
    # since artifactory only recognizes the lower case name.
    sec_dict['name'] = sec_dict['name'].lower()
    name = name.lower()
    group_config = str(sec_dict)

    result['original_message'] = ("Perform state '%s' against target '%s' "
                                  "within artifactory '%s'"
                                  % (state, name, artifactory_url))

    art_grp = art_base.ArtifactoryBase(
        artifactory_url=artifactory_url,
        name=name,
        art_config=group_config,
        username=username,
        password=auth_password,
        auth_token=auth_token,
        validate_certs=validate_certs,
        client_cert=client_cert,
        client_key=client_key,
        force_basic_auth=force_basic_auth,
        config_map=URI_CONFIG_MAP)
    art_base.run_module(module, art_grp, "groups", result,
                        fail_messages, group_config)


if __name__ == "__main__":
    main()
