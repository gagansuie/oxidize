[relay_servers]
%{ for name, server in servers ~}
${name} ansible_host=${server.primary_ipv4} ansible_user=ubuntu
%{ endfor ~}

[relay_servers:vars]
ansible_ssh_private_key_file=~/.ssh/latitude_oxidize
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
