#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: artifactory_repo

short_description: Provides management operations for repositories in JFrog Artifactory

version_added: "2.4"

description:
    - "Provides basic management operations against repositories JFrog Artifactory 5+."

options:
    artifactory_url:
        description:
            - The target URL for managing artifactory. For certain operations,
              you can include the repository key appended to the end of the
              url.
        required: true
    repo:
        description:
            - Name of the target repo to perform CRUD operations against.
        required: false
    repo_position:
        description:
            - Sets the resolution order for which repos of the same type are
              queried. This governs the order local, remote repositories
              and other virtual repositories are listed in the virtual
              repository configuration. By default, this is ignored so that
              the order is governed by the order of creation.
        required: false
    repo_config:
        description:
            - The configuration for the given repository in json format.
              'rclass' must be defined for all create calls. If
              creating a 'virtual' repository, 'packageType'
              must be defined with an appropriate type. If creating
              a 'remote' repository, 'url' must be defined in the
              configuration.
        required: false
    username:
        description:
            - username to be used in Basic Auth against Artifactory. Not
              required if using auth_token for basic auth.
        required: false
    password:
        description:
            - password to be used in Basic Auth against Artifactory. Not
              required if using auth_token for basic auth.
        required: false
    auth_token:
        description:
            - authentication token to be used in Basic Auth against
              Artifactory. Not required if using username/password for basic
              auth.
        required: false
    validate_certs:
        description:
            - True to validate SSL certificates, False otherwise.
        required: false
        choices:
          - True
          - False
        default: False
    client_cert:
        description:
            - PEM formatted certificate chain file to be used for SSL client
              authentication. This file can also include the key as well, and
              if the key is included, I(client_key) is not required
        required: false
    client_key:
        description:
            - PEM formatted file that contains your private key to be used for
              SSL client authentication. If I(client_cert) contains both the
              certificate and key, this option is not required.
        required: false
    force_basic_auth:
        description:
            - The library used by the uri module only sends authentication
              information when a webservice responds to an initial request
              with a 401 status. Since some basic auth services do not properly
              send a 401, logins will fail. This option forces the sending of
              the Basic authentication header upon initial request.
        required: false
        choices:
          - True
          - False
        default: False
    state:
        description:
            - The state the repository should be in. 'present' ensures that a
              repository is created and/or it is updated, but not replaced.
              'absent' ensures that the repository is deleted. 'read' will
              return the configuration if the repository exists.
        required: false
        choices:
          - present
          - absent
          - read
        default: present

author:
    - Kyle Haley (@quade)
'''

EXAMPLES = '''
# Create a local repository in artifactory with auth_token with minimal
# config requirements
- name: create test-local-creation repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    auth_token: my_token
    repo: "test-local-creation"
    state: present
    repo_config: '{"rclass": "local"}'

# Delete a local repository in artifactory with auth_token
- name: delete test-local-delete repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    auth_token: your_token
    repo: "test-local-delete"
    state: absent

# Create a remote repository in artifactory with username/password with
# minimal config requirements
- name: create test-remote-creation repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    username: your_username
    password: your_pass
    repo: "test-remote-creation"
    state: present
    repo_config: '{"rclass": "remote", "url": "http://http://host:port/some-repo"}'

# Create a virtual repository in artifactory with auth_token with
# minimal config requirements
- name: create test-remote-creation repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    auth_token: your_token
    repo: "test-virtual-creation"
    state: present
    repo_config: '{"rclass": "virtual", "packageType": "generic"}'

# Update a virtual repository in artifactory with username/password
- name: update test-virtual-update repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    username: your_username
    password: your_pass
    repo: "test-virtual-update"
    state: present
    repo_config: '{"description": "New public description."}'

# Update a virtual repository and register current config after update.
- name: update test-virtual-update repo
  artifactory_repo:
    artifactory_url: https://artifactory.repo.example.com
    auth_token: your_token
    repo: "test-virtual-update"
    state: present
    repo_config: '{"description": "New public description."}'
  register: test_virtual_config

# Repository config is in response for successful create/update calls,
# regardless if call resulted in a change. Successful delete calls
# contain the config of the repo just before deletion for later use in play.
- name: dump test_virtual_config config json
  debug:
    msg: '{{ test_virtual_config.config }}'
'''

RETURN = '''
original_message:
    description:
        - A brief sentence describing what action the module was attempting
          to take against which repository and what artifactory url.
    returned: success
    type: str
message:
    description: The result of the attempted action.
    returned: success
    type: str
config:
    description:
        - The configuration of a successfully created repository, an updated
          repository (whether or not changed=True), or the config
          of a repository that was successfully deleted.
    returned: success
    type: dict
'''


import ast
import json

import ansible.module_utils.six.moves.urllib.error as urllib_error
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url

LOCAL_RCLASS = "local"
REMOTE_RCLASS = "remote"
VIRTUAL_RCLASS = "virtual"

VALID_RCLASSES = [LOCAL_RCLASS, REMOTE_RCLASS, VIRTUAL_RCLASS]

REQUIRED_REPO_CONFIG = {
    "rclass":
        {"valid_values": VALID_RCLASSES,
         "rclass_requires": VALID_RCLASSES},
    "packageType":
        {"valid_values": ["bower",
                          "chef",
                          "composer",
                          "conan",
                          "debian",
                          "docker",
                          "gems",
                          "generic",
                          "gitlfs",
                          "gradle",
                          "ivy",
                          "maven",
                          "npm",
                          "nuget",
                          "puppet",
                          "pypi",
                          "sbt",
                          "vagrant",
                          "yum"],
         "rclass_requires": [VIRTUAL_RCLASS]},
    "url":
        {"valid_values": None,
         "rclass_requires": [REMOTE_RCLASS]}}


class ArtifactoryRepositoryManagement:
    def __init__(self, artifactory_url, repo=None, repo_position=None,
                 repo_config=None, username=None, password=None,
                 auth_token=None, validate_certs=False, client_cert=None,
                 client_key=None, force_basic_auth=False):
        self.artifactory_url = artifactory_url
        self.repo = repo
        self.repo_position = repo_position
        self.repo_config = repo_config

        self.username = username
        self.password = password
        self.auth_token = auth_token

        self.validate_certs = validate_certs
        self.client_cert = client_cert
        self.client_key = client_key
        self.force_basic_auth = force_basic_auth

        if self.repo:
            self.working_url = '%s/%s' % (self.artifactory_url, self.repo)
        else:
            self.working_url = self.artifactory_url

        self.headers = {"Content-Type": "application/json"}
        if auth_token:
            self.headers["X-JFrog-Art-Api"] = auth_token

    def get_repositories(self):
        return self.__query_artifactory(self.artifactory_url, 'GET')

    def get_repository_config(self):
        return self.__query_artifactory(self.working_url, 'GET')

    def create_repository(self):
        """ create_repository functions as both CREATE and REPLACE calls """

        serial_config_data = self._serialize_config_data(self.repo_config)
        self.validate_config_required_values(serial_config_data)

        create_repo_url = self.working_url
        if self.repo_position:
            if isinstance(self.repo_position, int):
                create_repo_url = '%s?pos=%d' % (create_repo_url,
                                                 self.repo_position)
            else:
                raise ValueError("repo_position must be an integer.")

        return self.__query_artifactory(create_repo_url, 'PUT',
                                        data=serial_config_data)

    def update_repository_config(self):
        serial_config_data = self._serialize_config_data(self.repo_config)
        return self.__query_artifactory(self.working_url, 'POST',
                                        data=serial_config_data)

    def delete_repository(self):
        return self.__query_artifactory(self.working_url, 'DELETE')

    def __query_artifactory(self, url, method, data=None):
        if self.auth_token:
            response = open_url(url, data=data, headers=self.headers,
                                method=method,
                                validate_certs=self.validate_certs,
                                client_cert=self.client_cert,
                                client_key=self.client_key,
                                force_basic_auth=self.force_basic_auth)
        else:
            response = open_url(url, data=data, headers=self.headers,
                                method=method,
                                validate_certs=self.validate_certs,
                                client_cert=self.client_cert,
                                client_key=self.client_key,
                                force_basic_auth=self.force_basic_auth,
                                url_username=self.username,
                                url_password=self.password)
        return response

    def _serialize_config_data(self, config_data):
        if not config_data:
            raise InvalidConfigurationData("Config is null or empty.")
        serial_config_data = self.get_serialized_config_to_json(config_data)
        return serial_config_data

    def get_serialized_config_to_json(self, config_data):
        serial_config_data = ''
        if isinstance(config_data, dict):
            serial_config_data = json.dumps(config_data)
        elif isinstance(config_data, str):
            try:
                test_dict = ast.literal_eval(config_data)
                if isinstance(test_dict, dict):
                    serial_config_data = json.dumps(test_dict)
                else:
                    raise ValueError()
            except ValueError:
                raise ConfigValueTypeMismatch("Configuration data provided "
                                              "is not valid json.")
        else:
            raise ConfigValueTypeMismatch("Configuration data provided is not "
                                          "valid json.")
        return serial_config_data

    def validate_config_required_values(self, serial_config_data):
        dict_config_data = ast.literal_eval(serial_config_data)
        self.validate_config_against_rclass(dict_config_data)
        for config_key in dict_config_data:
            if config_key in REQUIRED_REPO_CONFIG:
                self.validate_config_value(config_key,
                                           dict_config_data[config_key])

    def validate_config_value(self, config_key, config_val):
        valid_values = REQUIRED_REPO_CONFIG[config_key]["valid_values"]
        if valid_values and config_val not in valid_values:
            except_message = ("'%s' is not a valid value for key %s"
                              % (config_val, config_key))
            raise InvalidConfigurationData(except_message)

    def validate_config_against_rclass(self, dict_config_data):
        if "rclass" in dict_config_data:
            rclass_in_config = dict_config_data["rclass"]
        else:
            raise InvalidConfigurationData("rclass key is missing in config.")

        if rclass_in_config not in VALID_RCLASSES:
            raise InvalidConfigurationData("rclass is not valid.")

        required_keys = []
        for required_key in REQUIRED_REPO_CONFIG:
            key_definition = REQUIRED_REPO_CONFIG[required_key]
            if rclass_in_config in key_definition["rclass_requires"]:
                required_keys.append(required_key)

        for required_key in required_keys:
            if required_key not in dict_config_data:
                except_message = ("rclass '%s' requires defined config key "
                                  "'%s'" % (rclass_in_config, required_key))
                raise InvalidConfigurationData(except_message)


class ConfigValueTypeMismatch(Exception):
    pass


class InvalidConfigurationData(Exception):
    pass


def run_module():
    state_map = ['present', 'absent', 'read']
    module_args = dict(
        artifactory_url=dict(type='str', required=True),
        repo=dict(type='str', default=None),
        repo_position=dict(type='int', default=None),
        repo_config=dict(type='str', default=None),
        username=dict(type='str', default=None),
        password=dict(type='str', no_log=True, default=None),
        auth_token=dict(type='str', no_log=True, default=None),
        validate_certs=dict(type='bool', default=False),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        force_basic_auth=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=state_map),
    )

    result = dict(
        changed=False,
        original_message='',
        message='',
        config=dict()
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[['username', 'password']],
        required_one_of=[['password', 'auth_token']],
        mutually_exclusive=[['password', 'auth_token']],
        required_if=[['state', 'present', ['artifactory_url', 'repo',
                                           'repo_config']],
                     ['state', 'absent', ['artifactory_url', 'repo']],
                     ['state', 'read', ['artifactory_url', 'repo']]],
        supports_check_mode=True,
    )

    artifactory_url = module.params['artifactory_url']
    repository = module.params['repo']
    repo_position = module.params['repo_position']
    repo_config = module.params['repo_config']
    username = module.params['username']
    password = module.params['password']
    auth_token = module.params['auth_token']
    validate_certs = module.params['validate_certs']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    force_basic_auth = module.params['force_basic_auth']
    state = module.params['state']

    result['original_message'] = ("Perform state '%s' against repo '%s' "
                                  "within artifactory '%s'"
                                  % (state, repository, artifactory_url))

    if module.check_mode:
        result['message'] = 'check_mode success'
        module.exit_json(**result)

    artifactory_repo = ArtifactoryRepositoryManagement(
        artifactory_url=artifactory_url,
        repo=repository,
        repo_position=repo_position,
        repo_config=repo_config,
        username=username,
        password=password,
        auth_token=auth_token,
        validate_certs=validate_certs,
        client_cert=client_cert,
        client_key=client_key,
        force_basic_auth=force_basic_auth)

    failure_message = None
    try:
        all_repos = artifactory_repo.get_repositories()
    except urllib_error.HTTPError as e:
        failure_message = e.read()
        # Fail fast here, no other feature will work if this call fails
        module.fail_json(msg=failure_message, **result)

    all_repos = json.loads(all_repos.read())
    repository_exists = False
    for repo in all_repos:
        if 'key' in repo and repo['key'] == repository:
            repository_exists = True

    repo_not_exists_msg = ("Repository '%s' does not exist." % repository)
    resp_is_invalid_failure = ("An unknown error occurred while attempting to "
                               "'%s' repo '%s'. Response should "
                               "not be None.")
    if state == 'read':
        if not repository_exists:
            result['message'] = repo_not_exists_msg
        else:
            try:
                resp = artifactory_repo.get_repository_config()
                if resp:
                    result['message'] = ("Successfully read config "
                                         "on repo '%s'." % repository)
                    result['config'] = json.loads(resp.read())
                    result['changed'] = True
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, repository))
            except urllib_error.HTTPError as e:
                failure_message = e.read()
    elif state == 'present':
        # If the repo doesn't exist, create it.
        # If the repo does exist, perform an update on it ONLY if
        # configuration supplied has values that don't match the remote
        # config.
        try:
            if not repository_exists:
                resp = artifactory_repo.create_repository()
                if resp:
                    result['message'] = resp.read()
                    result['changed'] = True
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, repository))
            else:
                current_config = artifactory_repo.get_repository_config()
                current_config = json.loads(current_config.read())
                desired_config = ast.literal_eval(repo_config)
                # Compare desired config with current config against repo.
                # If config values are identical, don't update.
                resp = None
                for key in current_config:
                    if key in desired_config:
                        if desired_config[key] != current_config[key]:
                            resp = artifactory_repo.update_repository_config()
                # To guarantee idempotence. If underlying libraries don't
                # throw an exception, it could incorrectly report a success
                # when there was actually a failure.
                if resp:
                    result['message'] = ("Successfully updated config "
                                         "on repo '%s'." % repository)
                    result['changed'] = True
                else:
                    # Config values were identical.
                    result['message'] = ("Repo '%s' was not updated because "
                                         "config was identical." % repository)
            # Attach the repository config to result
            current_config = artifactory_repo.get_repository_config()
            result['config'] = json.loads(current_config.read())
        except urllib_error.HTTPError as http_e:
            failure_message = http_e.read()
        except ConfigValueTypeMismatch as cvtm:
            failure_message = cvtm.message
        except InvalidConfigurationData as icd:
            failure_message = icd.message
    elif state == 'absent':
        if not repository_exists:
            result['message'] = repo_not_exists_msg
        else:
            try:
                # save config for output on successful delete so it can be
                # used later in play if recreating repositories
                current_config = artifactory_repo.get_repository_config()
                resp = artifactory_repo.delete_repository()
                if resp:
                    result['message'] = ("Successfully deleted repo '%s'."
                                         % repository)
                    result['changed'] = True
                    result['config'] = json.loads(current_config.read())
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, repository))
            except urllib_error.HTTPError as e:
                result['message'] = ("Failed to delete repo '%s' due to "
                                     "an exception." % repository)
                failure_message = http_e.read()

    if failure_message:
        module.fail_json(msg=failure_message, **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()