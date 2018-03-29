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
module: artifactory_security

short_description: Provides management operations for security operations in JFrog Artifactory

version_added: "2.5"

description:
    - Provides basic management operations against security operations in JFrog
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
            - Name of the user target to perform
              CRUD operations against.
        required: true
    user_config:
        description:
            - The string representations of the JSON used to create the target
              security user. Please reference the JFrog Artifactory Security
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
            - The state the target user should be in.
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
    user_config_dict:
        description:
            - A dictionary in yaml format of valid configuration values against
              a user. These dictionary values must match any other values
              passed in, such as those within top-level parameters or within
              the configuration string in user_config.
    password:
        description:
            - The password used for creating a new user within Artifactory. It
              will not be displayed in the log output.
    email:
        description:
            - The email used for creating a new user within Artifactory.

author:
    - Kyle Haley (@quadewarren)
'''

EXAMPLES = '''
# Create a user using top-level parameters
- name: create a temp user
  artifactory_users:
    artifactory_url: http://artifactory.url.com/artifactory/api/security/users
    auth_token: MY_TOKEN
    name: temp-user
    email: whatever@email.com
    password: whatever
    state: present

# Update the user config using top-level parameters
- name: update a user config using top-level parameters
  artifactory_users:
    artifactory_url: http://artifactory.url.com/artifactory/api/security/users
    auth_token: MY_TOKEN
    name: temp-user
    email: whatever@diffemail.com
    state: present

- name: delete the temp user
  artifactory_users:
    artifactory_url: http://artifactory.url.com/artifactory/api/security/users
    auth_token: MY_TOKEN
    name: temp-user
    state: absent
'''

RETURN = '''
original_message:
    description:
        - A brief sentence describing what action the module was attempting
          to take against the user configuration and what artifactory url.
    returned: success
    type: str
message:
    description: The result of the attempted action.
    returned: success
    type: str
config:
    description:
        - The configuration of a successfully created user,
          an updated user (whether or not changed=True), or
          the config of a user that was successfully deleted.
    returned: success
    type: dict
'''
import ast

import ansible.module_utils.artifactory as art_base

from ansible.module_utils.basic import AnsibleModule


USER_CONFIG_MAP = {
    "email":
        {"always_required": True},
    "password":
        {"always_required": True}}
URI_CONFIG_MAP = {"api/security/users": USER_CONFIG_MAP}


def main():
    state_map = ['present', 'absent', 'read', 'list']
    module_args = dict(
        artifactory_url=dict(type='str', required=True),
        name=dict(type='str', default=''),
        user_config=dict(type='str', default=None),
        username=dict(type='str', default=None),
        auth_password=dict(type='str', no_log=True, default=None),
        auth_token=dict(type='str', no_log=True, default=None),
        validate_certs=dict(type='bool', default=False),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        force_basic_auth=dict(type='bool', default=False),
        state=dict(type='str', default='read', choices=state_map),
        user_config_dict=dict(type='dict', default=dict()),
        password=dict(type='str', no_log=True, default=None),
        email=dict(type='str', default=None),
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
    user_config = module.params['user_config']
    username = module.params['username']
    auth_password = module.params['auth_password']
    auth_token = module.params['auth_token']
    validate_certs = module.params['validate_certs']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    force_basic_auth = module.params['force_basic_auth']
    state = module.params['state']
    user_config_dict = module.params['user_config_dict']

    if user_config:
        # temporarily convert to dict for validation
        user_config = ast.literal_eval(user_config)

    fail_messages = []

    fails = art_base.validate_config_params(user_config, user_config_dict,
                                            'user_config',
                                            'user_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('name', module, user_config,
                                               user_config_dict,
                                               'user_config',
                                               'user_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('password', module, user_config,
                                               user_config_dict,
                                               'user_config',
                                               'user_config_dict')
    fail_messages.extend(fails)
    fails = art_base.validate_top_level_params('email', module, user_config,
                                               user_config_dict,
                                               'user_config',
                                               'user_config_dict')
    fail_messages.extend(fails)

    # Populate failure messages
    failure_message = "".join(fail_messages)

    # Conflicting config values should not be resolved
    if failure_message:
        module.fail_json(msg=failure_message, **result)

    sec_dict = dict()
    if module.params['name']:
        sec_dict['name'] = module.params['name']
    if module.params['password']:
        sec_dict['password'] = module.params['password']
    if module.params['email']:
        sec_dict['email'] = module.params['email']
    if user_config:
        sec_dict.update(user_config)
    if user_config_dict:
        sec_dict.update(user_config_dict)
    user_config = str(sec_dict)

    result['original_message'] = ("Perform state '%s' against target '%s' "
                                  "within artifactory '%s'"
                                  % (state, name, artifactory_url))

    art_sec = art_base.ArtifactoryBase(
        artifactory_url=artifactory_url,
        name=name,
        art_config=user_config,
        username=username,
        password=auth_password,
        auth_token=auth_token,
        validate_certs=validate_certs,
        client_cert=client_cert,
        client_key=client_key,
        force_basic_auth=force_basic_auth,
        config_map=URI_CONFIG_MAP)
    ignore_keys = []
    art_base.run_module(module, art_sec, "users", result,
                        fail_messages, user_config, ignore_keys=ignore_keys)


if __name__ == "__main__":
    main()
