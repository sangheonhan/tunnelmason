package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type Tunnel struct {
	LocalHost  string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
}

type Config struct {
	SSHServe string   `json:"ssh_server"`
	SSHPort  int      `json:"ssh_port"`
	Username string   `json:"username"`
	SSHKey   string   `json:"ssh_key"`
	Tunnels  []Tunnel `json:"tunnels"`
}

// ipExists checks if a given IP is assigned
func ipExists(ip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ip {
				return true
			}
		}
	}
	return false
}

// generateCommands returns add and delete commands for the given IP
func generateCommands(ip string) ([]string, []string, error) {
	var iface string
	var addCmd, delCmd []string
	switch runtime.GOOS {
	case "linux":
		iface = "lo"
		addCmd = []string{"ip", "addr", "add", ip + "/32", "dev", iface}
		delCmd = []string{"ip", "addr", "del", ip + "/32", "dev", iface}
	case "darwin":
		iface = "lo0"
		addCmd = []string{"ifconfig", iface, "alias", ip + "/32"}
		delCmd = []string{"ifconfig", iface, "-alias", ip}
	default:
		return nil, nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	return addCmd, delCmd, nil
}

// runCommand executes a sudo command
func runCommand(cmd []string) error {
	// Execute the command directly without sudo
	return exec.Command(cmd[0], cmd[1:]...).Run()
}

func forwardTunnel(localHost string, localPort int, remoteHost string, remotePort int, sshClient *ssh.Client) {
	// determine bind address
	var bindAddr string
	if localHost == "" {
		bindAddr = fmt.Sprintf(":%d", localPort)
	} else {
		bindAddr = fmt.Sprintf("%s:%d", localHost, localPort)
	}
	local, err := net.Listen("tcp", bindAddr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer local.Close()
	fmt.Printf("Listening on %s for connections to %s:%d\n", bindAddr, remoteHost, remotePort)

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

	// assign temporary IPs and setup cleanup
	delCmds := [][]string{}
	for _, t := range config.Tunnels {
		if t.LocalHost != "" && !ipExists(t.LocalHost) {
			add, del, err := generateCommands(t.LocalHost)
			if err != nil {
				fmt.Println("IP setup error:", err)
				os.Exit(1)
			}
			if err := runCommand(add); err != nil {
				fmt.Println("Failed to add IP:", err)
				os.Exit(1)
			}
			delCmds = append(delCmds, del)
		}
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		for _, cmd := range delCmds {
			if err := runCommand(cmd); err != nil {
				fmt.Println("Failed to remove IP:", err)
			}
		}
		os.Exit(0)
	}()

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
		go forwardTunnel(tunnel.LocalHost, tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort, sshClient)
	}

	select {} // keep the main function alive
}
