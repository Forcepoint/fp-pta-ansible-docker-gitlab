# docker-gitlab

Setup an HTTPS enabled gitlab server in a docker container.

## Disaster Recovery

If you have utilized the backup-local role to make backups, follow these steps to recover from backups of the data...

1. For the sake of this example, let's assume...
   1. Your docker data (var: docker_gitlab_root_data_dir) is located `/home/service/data`.
   1. You backups (var: backup_local_destination) are all located `/home/service/data/backups`.
1. Run ansible to setup the application for you. As long as ansible completes, you're good to proceed.
1. Stop the running docker container.

        docker container stop gitlab
       
1. Delete the docker container. This is to ensure the volumes are released.

        docker container rm gitlab
       
1. Delete the docker data.

        sudo rm -rf /home/service/data/gitlab/config
        sudo rm -rf /home/service/data/gitlab/data

1. Extract the backups.

        sudo tar -C / -xvf /home/service/data/backups/gitlab_config_DATETIME.tar
        sudo tar -C / -xvf /home/service/data/backups/gitlab_data_DATETIME.tar

1. Run ansible to start the application.

## Requirements

Run the role docker-host on the host. The following files are required to be present. 
Ensure they're vaulted before committing them to source control.

* files/<docker_gitlab_dns>.key
* files/<docker_gitlab_dns>.pem

## Role Variables

### REQUIRED

* docker_gitlab_version: The version of Gitlab to use.
* docker_gitlab_display_name: The name to be displayed in emails (EX: SLC Gitlab).
* docker_gitlab_dns: The DNS name of the intended Gitlab instance.
* docker_gitlab_omnibus_config: The omnibus config to load Gitlab with. 
  See the following links for further help.
  * https://docs.gitlab.com/omnibus/docker/#pre-configure-docker-container
  * https://technet.microsoft.com/en-us/library/aa996205(v=exchg.65).aspx
  * https://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx
  * https://confluence.atlassian.com/kb/how-to-write-ldap-search-filters-792496933.html
  * Microsoft Exchange https://docs.gitlab.com/omnibus/settings/smtp.html#microsoft-exchange-no-authentication
  * http://www.monblocnotes.com/node/2250
  * For HTTPS handling in association with the reverse proxy. Users connect to
    the reverse proxy using HTTPS. The reverse proxy connects to GitLab using HTTP.

### OPTIONAL

* docker_gitlab_root_data_dir: The directory to store the data in relevant to running the docker containers.
* docker_gitlab_certs_to_trust: A list of certificates to copy into Gitlab's trust certs directory and 
  whether they are remote or not.
  Useful if you're using a private CA for Gitlab's web certificates. 
  Also useful if Gitlab needs to interact with other applications who's certificates 
  don't validate with the already loaded public CAs. For example, if an intermediate 
  certificate is needed for communication with your JIRA server.

## Dependencies

None

## Example Playbook

    - hosts: servers
      vars:
        docker_gitlab_version: 12.10.1
        docker_gitlab_display_name: "COMPANY Gitlab"
        docker_gitlab_dns: gitlab.COMPANY.com
        docker_gitlab_ldap_password: 'encrypted string of ansible vaulted password'
        docker_gitlab_omnibus_config: |
          external_url 'https://{{ docker_gitlab_dns }}'
          nginx['redirect_http_to_https'] = true
          nginx['ssl_certificate'] = '/etc/gitlab/ssl/{{ docker_gitlab_dns }}.pem'
          nginx['ssl_certificate_key'] = '/etc/gitlab/ssl/{{ docker_gitlab_dns }}.key'
          gitlab_rails['backup_path'] = '/var/opt/gitlab/backups'
          gitlab_rails['smtp_enable'] = true
          gitlab_rails['smtp_address'] = "mail.COMPANY.com"
          gitlab_rails['smtp_port'] = 25
          gitlab_rails['smtp_domain'] = "COMPANY.com"
          gitlab_rails['smtp_authentication'] = false
          gitlab_rails['smtp_enable_starttls_auto'] = false
          gitlab_rails['ldap_enabled'] = true
          gitlab_rails['ldap_servers'] = YAML.load <<-'EOS'
            main:
              label: 'FDO'
              host: 'ldap.COMPANY.com'
              port: 636
              uid: 'sAMAccountName'
              bind_dn: 'CN=service-gitlab-user,OU=Service Accounts,OU=_Users,DC=COMPANY,DC=COM'
              password: '{{ docker_gitlab_ldap_password }}'
              encryption: 'start_tls' # "start_tls" or "simple_tls" or "plain"
              verify_certificates: true
              tls_options:
                ca_file: '/etc/gitlab/trusted-certs/private_ca.pem'
              active_directory: true
              allow_username_or_email_login: false
              block_auto_created_users: false
              base: 'OU=_Users,DC=COMPANY,DC=COM'
          EOS
        docker_gitlab_certs_to_trust:
          # You baked your private CA certificate into the base image, use remote_src yes.
          - { path: '/etc/pki/ca-trust/custom/private_ca.pem', remote_src: yes }
          # The JIRA intermediate cert is only needed for Gitlab. 
          # May make more sense to get it from the playbook than to bake it into the base image. Use remote_src no.
          - { path: 'files/jira_intermediate_ca.pem', remote_src: no }
      roles:
         - role: docker-gitlab

## License

BSD-3-Clause

## Author Information

Jeremy Cornett <jeremy.cornett@forcepoint.com>
