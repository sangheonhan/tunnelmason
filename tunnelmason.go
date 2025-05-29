package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Tunnel struct {
	LocalHost  string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
}

type Config struct {
	SSHServer          string   `json:"ssh_server"`
	SSHPort            int      `json:"ssh_port"`
	Username           string   `json:"username"`
	SSHKey             string   `json:"ssh_key"`
	KnownHostsFile     string   `json:"known_hosts_file,omitempty"`
	StrictHostKeyCheck bool     `json:"strict_host_key_check"`
	Tunnels            []Tunnel `json:"tunnels"`
}

type TunnelManager struct {
	config    Config
	sshClient *ssh.Client
	listeners []net.Listener
	delCmds   [][]string
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

func NewTunnelManager(configPath string) (*TunnelManager, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	if config.KnownHostsFile == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			config.KnownHostsFile = filepath.Join(homeDir, ".ssh", "known_hosts")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelManager{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func loadKnownHosts(knownHostsFile string) (ssh.HostKeyCallback, error) {
	if knownHostsFile == "" {
		return nil, fmt.Errorf("known_hosts file path is empty")
	}
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts file %s: %w", knownHostsFile, err)
	}

	return hostKeyCallback, nil
}

func addHostKey(knownHostsFile, hostname string, port int, key ssh.PublicKey) error {
	dir := filepath.Dir(knownHostsFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	file, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening known_hosts file: %w", err)
	}
	defer file.Close()

	var hostEntry string
	if port == 22 {
		hostEntry = hostname
	} else {
		hostEntry = fmt.Sprintf("[%s]:%d", hostname, port)
	}

	line := fmt.Sprintf("%s %s %s\n", hostEntry, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
	if _, err := file.WriteString(line); err != nil {
		return fmt.Errorf("writing to known_hosts file: %w", err)
	}

	return nil
}

func getHostKeyFingerprint(key ssh.PublicKey) (string, string) {
	hash := sha256.Sum256(key.Marshal())
	sha256Fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])

	hash2 := md5.Sum(key.Marshal())
	md5Fingerprint := "MD5:" + hex.EncodeToString(hash2[:])

	return sha256Fingerprint, md5Fingerprint
}

func promptHostKeyApproval(hostname string, port int, key ssh.PublicKey) bool {
	sha256Fp, md5Fp := getHostKeyFingerprint(key)

	fmt.Printf("\nWARNING: The authenticity of host '%s' can't be established.\n", hostname)
	fmt.Printf("%s key fingerprint is %s\n", key.Type(), sha256Fp)
	fmt.Printf("%s key fingerprint is %s (legacy)\n", key.Type(), md5Fp)
	fmt.Print("Are you sure you want to continue connecting? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "yes" || response == "y"
}

func (tm *TunnelManager) createHostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if tm.config.KnownHostsFile != "" {
			hostKeyCallback, err := loadKnownHosts(tm.config.KnownHostsFile)
			if err != nil {
				log.Printf("Warning: Could not load known_hosts file: %v", err)
			} else {
				err = hostKeyCallback(hostname, remote, key)
				if err == nil {
					return nil
				}

				if tm.config.StrictHostKeyCheck {
					return fmt.Errorf("host key verification failed: %w", err)
				}
			}
		}

		if !tm.config.StrictHostKeyCheck {
			port := tm.config.SSHPort
			if !promptHostKeyApproval(hostname, port, key) {
				return fmt.Errorf("host key verification rejected by user")
			}

			if tm.config.KnownHostsFile != "" {
				if err := addHostKey(tm.config.KnownHostsFile, hostname, port, key); err != nil {
					log.Printf("Warning: Could not add key to known_hosts: %v", err)
				} else {
					log.Printf("Host key added to %s", tm.config.KnownHostsFile)
				}
			}
			return nil
		}

		return fmt.Errorf("host key verification failed: unknown host")
	}
}

func (tm *TunnelManager) setupIPs() error {
	for _, t := range tm.config.Tunnels {
		if t.LocalHost != "" && !ipExists(t.LocalHost) {
			add, del, err := generateCommands(t.LocalHost)
			if err != nil {
				return fmt.Errorf("generating IP commands: %w", err)
			}

			log.Printf("Adding IP address: %s", t.LocalHost)
			if err := runCommand(add); err != nil {
				return fmt.Errorf("adding IP %s: %w", t.LocalHost, err)
			}
			tm.delCmds = append(tm.delCmds, del)
		}
	}
	return nil
}

func (tm *TunnelManager) cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, listener := range tm.listeners {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}

	if tm.sshClient != nil {
		if err := tm.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}

	for _, cmd := range tm.delCmds {
		log.Printf("Removing IP address")
		if err := runCommand(cmd); err != nil {
			log.Printf("Failed to remove IP: %v", err)
		}
	}
}

func (tm *TunnelManager) connectSSH() error {
	key, err := os.ReadFile(tm.config.SSHKey)
	if err != nil {
		return fmt.Errorf("reading SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: tm.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: tm.createHostKeyCallback(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", tm.config.SSHServer, tm.config.SSHPort)
	log.Printf("Connecting to SSH server: %s", addr)

	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	tm.sshClient = sshClient
	return nil
}

func (tm *TunnelManager) startTunnels() error {
	for _, tunnel := range tm.config.Tunnels {
		if err := tm.startTunnel(tunnel); err != nil {
			return fmt.Errorf("starting tunnel %s:%d: %w", tunnel.LocalHost, tunnel.LocalPort, err)
		}
	}
	return nil
}

func (tm *TunnelManager) startTunnel(tunnel Tunnel) error {
	bindAddr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	if tunnel.LocalHost == "" {
		bindAddr = fmt.Sprintf(":%d", tunnel.LocalPort)
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", bindAddr, err)
	}

	tm.mu.Lock()
	tm.listeners = append(tm.listeners, listener)
	tm.mu.Unlock()

	log.Printf("Tunnel started: %s -> %s:%d", bindAddr, tunnel.RemoteHost, tunnel.RemotePort)

	tm.wg.Add(1)
	go tm.handleTunnel(listener, tunnel)

	return nil
}

func (tm *TunnelManager) handleTunnel(listener net.Listener, tunnel Tunnel) {
	defer tm.wg.Done()
	defer listener.Close()

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			log.Printf("Accept error for tunnel %s:%d: %v", tunnel.LocalHost, tunnel.LocalPort, err)
			continue
		}

		tm.wg.Add(1)
		go tm.handleConnection(conn, tunnel)
	}
}

func (tm *TunnelManager) handleConnection(localConn net.Conn, tunnel Tunnel) {
	defer tm.wg.Done()
	defer localConn.Close()

	remoteAddr := fmt.Sprintf("%s:%d", tunnel.RemoteHost, tunnel.RemotePort)
	remoteConn, err := tm.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Failed to dial remote %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	ctx, cancel := context.WithCancel(tm.ctx)
	defer cancel()

	go tm.copyData(ctx, localConn, remoteConn, cancel)
	go tm.copyData(ctx, remoteConn, localConn, cancel)

	<-ctx.Done()
}

func (tm *TunnelManager) copyData(ctx context.Context, dst, src net.Conn, cancel context.CancelFunc) {
	defer cancel()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	_, err := io.Copy(dst, src)
	if err != nil && ctx.Err() == nil {
		log.Printf("Copy error: %v", err)
	}
}

func (tm *TunnelManager) Run() error {
	if err := tm.setupIPs(); err != nil {
		return err
	}

	if err := tm.connectSSH(); err != nil {
		return err
	}

	if err := tm.startTunnels(); err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Tunnel manager started. Press Ctrl+C to stop.")

	<-sigChan
	log.Println("Shutting down...")

	tm.cancel()
	tm.cleanup()
	tm.wg.Wait()

	log.Println("Shutdown complete")
	return nil
}

func ipExists(ip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error getting interfaces: %v", err)
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ip {
				return true
			}
		}
	}
	return false
}

func generateCommands(ip string) ([]string, []string, error) {
	var iface string
	var addCmd, delCmd []string

	switch runtime.GOOS {
	case "linux":
		iface = "lo"
		addCmd = []string{"sudo", "ip", "addr", "add", ip + "/32", "dev", iface}
		delCmd = []string{"sudo", "ip", "addr", "del", ip + "/32", "dev", iface}
	case "darwin":
		iface = "lo0"
		addCmd = []string{"sudo", "ifconfig", iface, "alias", ip + "/32"}
		delCmd = []string{"sudo", "ifconfig", iface, "-alias", ip}
	default:
		return nil, nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	return addCmd, delCmd, nil
}

func runCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("empty command")
	}
	return exec.Command(cmd[0], cmd[1:]...).Run()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	configFile := "tunnelmason.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	tm, err := NewTunnelManager(configFile)
	if err != nil {
		log.Fatalf("Creating tunnel manager: %v", err)
	}

	if err := tm.Run(); err != nil {
		log.Fatalf("Running tunnel manager: %v", err)
	}
}
