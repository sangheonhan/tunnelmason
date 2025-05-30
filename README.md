# Tunnel Mason

A robust SSH tunnel manager that provides multiple local port forwarding through SSH connections. Tunnel Mason automatically manages network interfaces, handles SSH authentication, and maintains persistent tunnels with proper cleanup.

## Features

- Multiple Tunnel Support: Configure and manage multiple SSH tunnels simultaneously
- Automatic IP Management: Automatically adds/removes local IP addresses on loopback interface
- Host Key Verification: Supports SSH known_hosts verification with interactive approval
- Graceful Shutdown: Proper cleanup of tunnels and IP addresses on termination
- Cross-Platform: Supports Linux and macOS
- Keep-Alive: Maintains persistent connections with TCP keep-alive
- Concurrent Connections: Handles multiple connections per tunnel

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd tunnel-mason

# Build the binary
go build -o tunnelmason tunnelmason.go
```

## Configuration

Create a `tunnelmason.json` configuration file in the same directory as the binary:

```json
{
    "ssh_server": "your-server.example.com",
    "ssh_port": 22,
    "username": "your-username",
    "ssh_key": "/path/to/your/ssh/private_key",
    "known_hosts_file": "/path/to/your/known_hosts",
    "strict_host_key_check": true,
    "tunnels": [
        {
            "local_host": "192.168.1.100",
            "local_port": 80,
            "remote_host": "192.168.1.200",
            "remote_port": 9200
        },
        {
            "local_host": "192.168.1.101",
            "local_port": 80,
            "remote_host": "192.168.1.201",
            "remote_port": 80
        },
        {
            "local_port": 9200,
            "remote_host": "192.168.1.200",
            "remote_port": 9200
        }
    ]
}
```

### Configuration Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ssh_server` | string | Yes | SSH server hostname or IP address |
| `ssh_port` | int | Yes | SSH server port (typically 22) |
| `username` | string | Yes | SSH username for authentication |
| `ssh_key` | string | Yes | Path to SSH private key file |
| `known_hosts_file` | string | No | Path to SSH known_hosts file (defaults to `~/.ssh/known_hosts`) |
| `strict_host_key_check` | bool | No | Enable strict host key checking (default: false) |
| `tunnels` | array | Yes | Array of tunnel configurations |

### Tunnel Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `local_host` | string | No | Local IP address to bind to (if omitted, binds to all interfaces) |
| `local_port` | int | Yes | Local port to listen on |
| `remote_host` | string | Yes | Remote host to forward connections to |
| `remote_port` | int | Yes | Remote port to forward connections to |

## Usage

### Basic Usage

```bash
# Run with default config file (tunnelmason.json)
./tunnelmason

# Run with custom config file
./tunnelmason /path/to/custom-config.json
```

### Example Scenarios

#### 1. Database Access Through Bastion

```json
{
    "ssh_server": "bastion.example.com",
    "ssh_port": 22,
    "username": "admin",
    "ssh_key": "/home/user/.ssh/id_rsa",
    "tunnels": [
        {
            "local_port": 5432,
            "remote_host": "db.internal.example.com",
            "remote_port": 5432
        }
    ]
}
```

#### 2. Multiple Service Access with Specific IPs

```json
{
    "ssh_server": "gateway.example.com",
    "ssh_port": 22,
    "username": "developer",
    "ssh_key": "/home/user/.ssh/dev_key",
    "tunnels": [
        {
            "local_host": "10.0.0.100",
            "local_port": 80,
            "remote_host": "web1.internal",
            "remote_port": 8080
        },
        {
            "local_host": "10.0.0.101",
            "local_port": 80,
            "remote_host": "web2.internal",
            "remote_port": 8080
        }
    ]
}
```

## Host Key Management

### Strict Host Key Checking

When `strict_host_key_check` is enabled:

- Host keys must exist in the known_hosts file
- Connection fails if host key doesn't match or is missing

When disabled:

- Unknown hosts prompt for interactive approval
- Approved keys are automatically added to known_hosts file

### Interactive Host Key Approval

For unknown hosts, you'll see a prompt like:

```
WARNING: The authenticity of host 'example.com' can't be established.
RSA key fingerprint is SHA256:abcd1234...
RSA key fingerprint is MD5:12:34:56:78... (legacy)
Are you sure you want to continue connecting? (yes/no):
```

## Platform Support

### Linux

- Uses `ip addr` commands to manage loopback addresses
- Requires `sudo` privileges for IP management

### macOS

- Uses `ifconfig` commands to manage loopback aliases
- Requires `sudo` privileges for IP management

## Security Considerations

1. SSH Key Protection: Ensure SSH private keys have appropriate permissions (600)
2. Known Hosts: Use strict host key checking in production environments
3. Sudo Access: The application requires sudo privileges to manage IP addresses
4. Network Exposure: Be cautious when binding to specific IP addresses

## Troubleshooting

### Common Issues

#### Permission Denied for IP Management

```bash
# Ensure your user has sudo privileges
sudo visudo
# Add: username ALL=(ALL) NOPASSWD: /sbin/ip, /sbin/ifconfig
```

#### SSH Connection Failed

- Verify SSH server is accessible
- Check SSH key permissions and format
- Ensure username and server details are correct

#### Port Already in Use

- Check if another process is using the local port
- Use `netstat -tulpn | grep :PORT` to identify conflicting processes

### Logging

The application provides detailed logging including:

- SSH connection status
- Tunnel establishment
- IP address management
- Connection handling errors

## Signal Handling

The application gracefully handles shutdown signals:

- `SIGINT` (Ctrl+C)
- `SIGTERM`

On shutdown, it will:

1. Close all active tunnels
2. Remove added IP addresses
3. Close SSH connections
4. Wait for all goroutines to finish

## License

BSD 3-Clause License

Copyright (c) 2024, Tunnel Mason

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
