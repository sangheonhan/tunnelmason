package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
)

type Tunnel struct {
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
}

type Config struct {
	SSHServe  string   `json:"ssh_server"`
	SSHPort   int      `json:"ssh_port"`
	Username  string   `json:"username"`
	SSHKey    string   `json:"ssh_key"`
	Tunnels   []Tunnel `json:"tunnels"`
}

func forwardTunnel(localPort int, remoteHost string, remotePort int, sshClient *ssh.Client) {
	local, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer local.Close()
	fmt.Printf("Listening on port %d for connections to %s:%d\n", localPort, remoteHost, remotePort)

	for {
		localConn, err := local.Accept()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		remoteConn, err := sshClient.Dial("tcp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
		if err != nil {
			fmt.Printf("Could not open remote connection for port %d\n", localPort)
			localConn.Close()
			continue
		}

		go copyConn(localConn, remoteConn)
		go copyConn(remoteConn, localConn)
	}
}

func copyConn(writer, reader net.Conn) {
	defer writer.Close()
	defer reader.Close()
	io.Copy(writer, reader)
}

func main() {
	file, err := os.Open("tunnelmason.json")
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	config := Config{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	key, err := os.ReadFile(config.SSHKey)
	if err != nil {
		fmt.Println("Error reading key file:", err)
		return
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.SSHServe, config.SSHPort), sshConfig)
	if err != nil {
		fmt.Println("Failed to dial:", err)
		return
	}

	for _, tunnel := range config.Tunnels {
		go forwardTunnel(tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort, sshClient)
	}

	select {}  // keep the main function alive
}
