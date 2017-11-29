Artifactory
===========

A collection (hopefully) of modules for JFrog Artifactory to improve management of the system. Plans to submit to ansible proper. The role does not directly perform any actions.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
      - { role: quadewarren.artifactory }
      tasks:
      - name: create test-local-creation repo
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          auth_token: my_token
          repo: "test-local-creation"
          state: present
          repo_config: '{"rclass": "local"}'
      
      - name: Delete a local repository in artifactory with auth_token 
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          auth_token: your_token
          repo: "test-local-delete"
          state: absent
      
      - name: Create a minimal config remote repository with user/pass
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          username: your_username
          password: your_pass
          repo: "test-remote-creation"
          state: present
          repo_config: '{"rclass": "remote", "url": "http://http://host:port/some-repo"}'
      
      - name: Create a minimal config remote repository with auth_token 
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          auth_token: your_token
          repo: "test-virtual-creation"
          state: present
          repo_config: '{"rclass": "virtual", "packageType": "generic"}'
      
      - name: Update a virtual repository in artifactory with user/pass 
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          username: your_username
          password: your_pass
          repo: "test-virtual-update"
          state: present
          repo_config: '{"description": "New public description."}'
      
      - name: Update a virtual repository and register current config after update.
        artifactory_repo:
          artifactory_url: https://artifactory.repo.example.com
          auth_token: your_token
          repo: "test-virtual-update"
          state: present
          repo_config: '{"description": "New public description."}'
        register: test_virtual_config          

License
-------

GPLV3+ (submitting to Ansible proper, and this is how other modules are licensed)

Author Information
------------------

Written by Kyle Haley (quadewarren)
Rolified by Greg Swift
