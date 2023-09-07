# Tunnel Mason

Provide multiple local forwarding using SSH tunneling.

## Configuration

Config file is JSON format and file name is fixed to `tunnelmason.json`.

```json
{
    "ssh_server": "remote_server_ip",
    "ssh_port": 22,
    "username": "remote_server_username",
    "ssh_key": "path_to_ssh_key",
    "tunnels": [
        {"local_port": 8080, "remote_host": "192.168.0.10", "remote_port": 8080},
        {"local_port": 3306, "remote_host": "192.168.0.20", "remote_port": 3306},
        {"local_port": 9200, "remote_host": "127.0.0.1", "remote_port": 9200}
    ]
}
```
