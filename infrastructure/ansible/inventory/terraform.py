#!/usr/bin/env python3
"""
Dynamic inventory script that reads Terraform output.
Usage: ansible-playbook -i inventory/terraform.py playbooks/deploy.yml
"""

import json
import subprocess
import sys
import os

def get_terraform_output():
    """Get server IPs from Terraform output."""
    terraform_dir = os.path.join(os.path.dirname(__file__), '../../terraform')
    
    try:
        result = subprocess.run(
            ['terraform', 'output', '-json', 'server_ips'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception as e:
        print(f"Error getting Terraform output: {e}", file=sys.stderr)
    
    return {}

def main():
    server_ips = get_terraform_output()
    
    inventory = {
        'relay_servers': {
            'hosts': list(server_ips.keys()),
            'vars': {
                'ansible_ssh_private_key_file': '~/.ssh/latitude_oxidize',
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=no',
                'ansible_user': 'ubuntu'
            }
        },
        '_meta': {
            'hostvars': {
                name: {'ansible_host': ip}
                for name, ip in server_ips.items()
            }
        }
    }
    
    print(json.dumps(inventory, indent=2))

if __name__ == '__main__':
    main()
