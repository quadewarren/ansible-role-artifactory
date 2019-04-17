# Copyright (c) 2017 Kyle Haley, <kylephaley@gmail.com>

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import ansible.module_utils.six.moves.urllib.error as urllib_error
import ast
import json

from ansible.module_utils.six import iteritems
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.urls import open_url

"""
This is the general construction of the validation map passed in.
URI_CONFIG_MAP["uri_key"] is a substring of the target artifactory URL,
such as "api/repositories" or "api/security/groups". The need for URL substring
exists since some modules may need to cover multiple URLs, such as a security
module, which may need to touch on
"api/security/groups" or "api/security/users" or "api/security/permissions".

KEY_CONFIG_MAP = {
    "config_key":
        {"valid_values": list(),
         "required_keys": list(),
         "values_require_keys": dict(),
         "always_required": bool}}

URI_CONFIG_MAP = {
    "uri_key": KEY_CONFIG_MAP}
"""


class ArtifactoryBase(object):
    def __init__(self, username=None, password=None, artifactory_url=None,
                 auth_token=None, validate_certs=False, client_cert=None,
                 client_key=None, force_basic_auth=False, config_map=None,
                 name=None, art_config=None):
        self.username = username
        self.password = password
        self.auth_token = auth_token

        self.validate_certs = validate_certs
        self.client_cert = client_cert
        self.client_key = client_key
        self.force_basic_auth = force_basic_auth

        self.artifactory_url = artifactory_url
        self.name = name
        self.config_map = config_map
        self.art_config = art_config

        self.headers = {"Content-Type": "application/json"}
        if auth_token:
            self.headers["X-JFrog-Art-Api"] = auth_token

        if self.name:
            # escape invalid url characters
            self.working_url = '%s/%s' % (self.artifactory_url,
                                          quote(self.name))
        else:
            self.working_url = self.artifactory_url

    def get_artifactory_targets(self):
        return self.query_artifactory(self.artifactory_url, 'GET')

    def get_artifactory_target(self):
        return self.query_artifactory(self.working_url, 'GET')

    def delete_artifactory_target(self):
        return self.query_artifactory(self.working_url, 'DELETE')

    def create_artifactory_target(self):
        # This is not a mistake. POST == PUT in artifactory land
        method = 'PUT'
        serial_config_data = self.get_valid_conf(method)
        create_target_url = self.working_url
        return self.query_artifactory(create_target_url, method,
                                      data=serial_config_data)

    def update_artifactory_target(self):
        # This is not a mistake. PUT == POST in artifactory land
        method = 'POST'
        serial_config_data = self.get_valid_conf(method)
        return self.query_artifactory(self.working_url, method,
                                      data=serial_config_data)

    def get_valid_conf(self, method):
        config_dict = self.convert_config_to_dict(self.art_config)
        if method == 'PUT':
            self.validate_config_required_keys(self.artifactory_url,
                                               config_dict)
        self.validate_config_values(self.artifactory_url, config_dict)
        serial_config_data = self.serialize_config_data(config_dict)
        return serial_config_data

    def convert_config_to_dict(self, config):
        if isinstance(config, dict):
            return config
        else:
            error_occurred = False
            message = ""
            try:
                test_dict = ast.literal_eval(config)
                if isinstance(test_dict, dict):
                    config = test_dict
                else:
                    raise ValueError()
            except ValueError as ve:
                error_occurred = True
                message = str(ve)
            except SyntaxError as se:
                error_occurred = True
                message = str(se)

            if error_occurred:
                raise ConfigValueTypeMismatch("Configuration data provided "
                                              "is not valid json.\n %s"
                                              % message)
        return config

    def serialize_config_data(self, config_data):
        if not config_data or not isinstance(config_data, dict):
            raise InvalidConfigurationData("Config is null, empty, or is not"
                                           " a dictionary.")
        serial_config_data = json.dumps(config_data)
        return serial_config_data

    def query_artifactory(self, url, method, data=None):
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

    def validate_config_values(self, url, config_dict):
        validation_dict = self.get_uri_key_map(url, self.config_map)
        if not validation_dict or isinstance(validation_dict, bool):
            return
        for config_key in config_dict:
            if config_key in validation_dict:
                if "valid_values" in validation_dict[config_key]:
                    valid_values = validation_dict[config_key]["valid_values"]
                    config_val = config_dict[config_key]
                    if valid_values and config_val not in valid_values:
                        except_message = ("'%s' is not a valid value for "
                                          "key '%s'"
                                          % (config_val, config_key))
                        raise InvalidConfigurationData(except_message)

    def get_uri_key_map(self, url, uri_config_map):
        if not url or not uri_config_map:
            raise InvalidConfigurationData("url or config is None or empty."
                                           " url: %s, config: %s"
                                           % (url, uri_config_map))
        temp = None
        for uri_substr in uri_config_map:
            if uri_substr in url:
                temp = uri_config_map[uri_substr]
                break
        if temp:
            return temp
        else:
            raise InvalidArtifactoryURL("The url '%s' could not be "
                                        "mapped to a known set of "
                                        "configuration rules." % url)

    def validate_config_required_keys(self, url, config_dict):
        req_keys = self.get_always_required_keys(url, config_dict)
        for required in req_keys:
            if required not in config_dict:
                message = ("%s key is missing from config." % required)
                raise InvalidConfigurationData(message)
        return req_keys

    def get_always_required_keys(self, url, config_dict):
        """Return keys that are always required for creating a target."""
        validation_dict = self.get_uri_key_map(url, self.config_map)
        req_keys = list()
        # If the resulting validation dict is boolean True, then this just
        # verifies that the url is correct for this module. Return empty list.
        if not validation_dict or isinstance(validation_dict, bool):
            return req_keys
        for config_req in validation_dict:
            if "always_required" in validation_dict[config_req]:
                if validation_dict[config_req]["always_required"]:
                    req_keys.append(config_req)
        for config_key in config_dict:
            if config_key in validation_dict:
                valid_sub_dict = validation_dict[config_key]
                # If config_key exists, check if other keys are required.
                if "required_keys" in valid_sub_dict:
                    if isinstance(valid_sub_dict["required_keys"], list):
                        req_keys.extend(valid_sub_dict["required_keys"])
                    else:
                        raise InvalidConfigurationData(
                            "Values defined in 'required_keys' should be"
                            " a list. ['%s']['required_keys'] is not a"
                            " list." % config_key)
                # If config_key exists, check if the value of config_key
                # requires other keys.
                # If the value of the key 'rclass' is 'remote', then the 'url'
                # key must be defined. The value in the mapping should be a
                # list.
                if "values_require_keys" in valid_sub_dict:
                    config_value = config_dict[config_key]
                    val_req_keys = valid_sub_dict["values_require_keys"]
                    if val_req_keys and config_value in val_req_keys:
                        if isinstance(val_req_keys[config_value], list):
                            req_keys.extend(val_req_keys[config_value])
                        else:
                            raise InvalidConfigurationData(
                                "Values defined in in the dict"
                                " 'values_require_keys' should be lists."
                                " ['values_require_keys']['%s'] is not a"
                                " list." % config_value)
        return req_keys

    def compare_config(self, current, desired, ignore_keys=list()):
        def order_dict_sort_list(dictionary):
            result = {}
            for k, v in sorted(dictionary.items()):
                if isinstance(v, dict):
                    result[k] = order_dict_sort_list(v)
                elif isinstance(v, list):
                    result[k] = sorted(v)
                elif isinstance(v, str):
                    if v.isdigit():
                        result[k] = int(v)
                    else:
                        result[k] = v
                else:
                    result[k] = v
            return result

        s_current = order_dict_sort_list(current)
        s_desired = order_dict_sort_list(desired)
        return all(s_current[k] == s_desired[k]
                   for k in s_desired if k in s_current and
                   k not in ignore_keys)


class InvalidArtifactoryURL(Exception):
    pass


class ConfigValueTypeMismatch(Exception):
    pass


class InvalidConfigurationData(Exception):
    pass


TOP_LEVEL_FAIL = ("Conflicting config values. "
                  "top level parameter {1} != {0}[{1}]. "
                  "Only one config value need be set. ")


def validate_top_level_params(top_level_param, module, config, config_hash,
                              config_name, config_hash_name):
    """Validate top-level params against different configuration sources.
        These modules can have multiple configuration sources. If these sources
        have identical keys, but different values, aggregate error messages to
        alert the user for each one that does not match and the source.
        return a list of those messages.
    """
    validation_fail_messages = []
    config_hash_fail_msg = ""
    config_fail_msg = ""
    if not top_level_param or not module.params[top_level_param]:
        return validation_fail_messages
    value = module.params[top_level_param]
    if isinstance(value, list):
        value = sorted(value)
    if config_hash and top_level_param in config_hash:
        if isinstance(config_hash[top_level_param], list):
            config_hash[top_level_param] = sorted(config_hash[top_level_param])
        if value != config_hash[top_level_param]:
            config_hash_fail_msg = TOP_LEVEL_FAIL.format(config_hash_name,
                                                         top_level_param)
            validation_fail_messages.append(config_hash_fail_msg)
    if config and top_level_param in config:
        if isinstance(config[top_level_param], list):
            config[top_level_param] = sorted(config[top_level_param])
        if value != config[top_level_param]:
            config_fail_msg = TOP_LEVEL_FAIL.format(config_name,
                                                    top_level_param)
            validation_fail_messages.append(config_fail_msg)

    return validation_fail_messages


CONFIG_PARAM_FAIL = ("Conflicting config values. "
                     "{1}[{0}] != "
                     "{2}[{0}]. "
                     "Only one config value need be "
                     "set. ")


def validate_config_params(config, config_hash, config_name, config_hash_name):
    """Validate two different configuration sources.
        These modules can have multiple configuration sources. If these sources
        have identical keys, but different values, aggregate error messages to
        alert the user for each one that does not match and the source.
        return a list of those messages.
    """
    validation_fail_messages = []
    if not config_hash or not config:
        return validation_fail_messages
    for key, val in iteritems(config):
        if key in config_hash:
            if isinstance(config_hash[key], list):
                config_hash[key] = sorted(config_hash[key])
            if isinstance(config[key], list):
                config[key] = sorted(config[key])
            if config_hash[key] != config[key]:
                fail_msg = CONFIG_PARAM_FAIL.format(key, config_name,
                                                    config_hash_name)
                validation_fail_messages.append(fail_msg)
    return validation_fail_messages


def run_module(module, art_obj, message_noun, result, fail_messages,
               art_dict, ignore_keys=list()):
    state = module.params['state']
    artifactory_url = module.params['artifactory_url']
    target_name = module.params['name']
    art_config_str = art_obj.art_config
    art_target_exists = False
    try:
        art_obj.get_artifactory_target()
        art_target_exists = True
    except urllib_error.HTTPError as http_e:
        if http_e.getcode() == 400 and 'api/repositories' in artifactory_url:
            # Instead of throwing a 404, a 400 is thrown if a repo doesn't
            # exist. Have to fall through and assume the repo doesn't exist
            # and that another error did not occur. If there is another problem
            # it will have to be caught by try/catch blocks further below.
            pass
        elif (http_e.getcode() == 404 and
                ('api/security/groups' in artifactory_url or
                 'api/security/users' in artifactory_url or
                 'api/security/permissions' in artifactory_url)):
            # If 404, the target is just not found. Continue on.
            pass
        else:
            message = ("HTTP response code was '%s'. Response message was"
                       " '%s'. " % (http_e.getcode(), http_e.read()))
            fail_messages.append(message)
    except urllib_error.URLError as url_e:
        message = ("A generic URLError was thrown. URLError: %s" % str(url_e))
        fail_messages.append(message)

    try:
        # Now that configs are lined up, verify required values in configs
        if state == 'present':
            art_obj.validate_config_values(artifactory_url, art_dict)
            if not art_target_exists:
                art_obj.validate_config_required_keys(artifactory_url,
                                                      art_dict)
    except ConfigValueTypeMismatch as cvtm:
        fail_messages.append(cvtm.message + ". ")
    except InvalidConfigurationData as icd:
        fail_messages.append(icd.message + ". ")
    except InvalidArtifactoryURL as iau:
        fail_messages.append(iau.message + ". ")

    # Populate failure messages
    failure_message = "".join(fail_messages)

    if failure_message:
        module.fail_json(msg=failure_message, **result)

    if module.check_mode:
        result['message'] = 'check_mode success'
        module.exit_json(**result)

    art_targ_not_exists_msg = ("%s '%s' does not exist."
                               % (message_noun, target_name))
    resp_is_invalid_failure = ("An unknown error occurred while attempting to "
                               "'%s' %s '%s'. Response should "
                               "not be None.")
    resp = None
    try:
        if state == 'list':
            result['message'] = ("List of all artifactory targets against "
                                 "artifactory_url: %s" % artifactory_url)
            resp = art_obj.get_artifactory_targets()
            result['config'] = json.loads(resp.read())
        elif state == 'read':
            if not art_target_exists:
                result['message'] = art_targ_not_exists_msg
            else:
                resp = art_obj.get_artifactory_target()
                if resp:
                    result['message'] = ("Successfully read config "
                                         "on %s '%s'."
                                         % (message_noun, target_name))
                    result['config'] = json.loads(resp.read())
                    result['changed'] = True
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, message_noun, target_name))
        elif state == 'present':
            # If the target doesn't exist, create it.
            # If the target does exist, perform an update on it ONLY if
            # configuration supplied has values that don't match the remote
            # config.
            if not art_target_exists:
                result['message'] = ('Attempting to create %s: %s'
                                     % (message_noun, target_name))
                resp = art_obj.create_artifactory_target()
                if resp:
                    result['message'] = resp.read()
                    result['changed'] = True
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, message_noun, target_name))
            else:
                result['message'] = ('Attempting to update %s: %s'
                                     % (message_noun, target_name))
                current_config = art_obj.get_artifactory_target()
                current_config = json.loads(current_config.read())
                desired_config = ast.literal_eval(art_config_str)
                # Compare desired config with current config against target.
                # If config values are identical, don't update.
                config_identical = art_obj.compare_config(current_config,
                                                          desired_config)
                if not config_identical:
                    resp = art_obj.update_artifactory_target()
                    result['message'] = ("Successfully updated config "
                                         "on %s '%s'."
                                         % (message_noun, target_name))
                    result['changed'] = True
                else:
                    # Config values were identical.
                    result['message'] = ("%s '%s' was not updated because "
                                         "config was identical."
                                         % (message_noun, target_name))
            # Attach the artfactory target config to result
            current_config = art_obj.get_artifactory_target()
            result['config'] = json.loads(current_config.read())
        elif state == 'absent':
            if not art_target_exists:
                result['message'] = art_targ_not_exists_msg
            else:
                # save config for output on successful delete so it can be
                # used later in play if recreating targets
                current_config = art_obj.get_artifactory_target()
                resp = art_obj.delete_artifactory_target()
                if resp:
                    result['message'] = ("Successfully deleted %s '%s'."
                                         % (message_noun, target_name))
                    result['changed'] = True
                    result['config'] = json.loads(current_config.read())
                else:
                    failure_message = (resp_is_invalid_failure
                                       % (state, message_noun, target_name))
    except urllib_error.HTTPError as http_e:
        message = ("HTTP response code was '%s'. Response message was"
                   " '%s'. " % (http_e.getcode(), http_e.read()))
        failure_message = message
    except urllib_error.URLError as url_e:
        message = ("A generic URLError was thrown. URLError: %s"
                   % str(url_e))
        failure_message = message
    except SyntaxError as s_e:
        message = ("%s. Response from artifactory was malformed: '%s' . "
                   % (str(s_e), resp))
        failure_message = message
    except ValueError as v_e:
        message = ("%s. Response from artifactory was malformed: '%s' . "
                   % (str(v_e), resp))
        failure_message = message
    except ConfigValueTypeMismatch as cvtm:
        failure_message = cvtm.message
    except InvalidConfigurationData as icd:
        failure_message = icd.message

    if failure_message:
        module.fail_json(msg=failure_message, **result)

    module.exit_json(**result)
