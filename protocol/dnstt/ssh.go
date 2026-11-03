package dnstt

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/filemanager"

	"golang.org/x/crypto/ssh"
)

var _ N.Dialer = (*sshClient)(nil)

type sshClient struct {
	dialer            N.Dialer
	serverName        string
	user              string
	hostKey           []ssh.PublicKey
	hostKeyAlgorithms []string
	clientVersion     string
	authMethod        []ssh.AuthMethod
	clientAccess      sync.Mutex
	clientConn        net.Conn
	client            *ssh.Client
	streams           int
	closeIdle         bool
}

func newSSHClient(ctx context.Context, dialer N.Dialer, serverName string, options option.DNSTTSSHOptions) (*sshClient, error) {
	client := &sshClient{
		dialer:            dialer,
		serverName:        serverName,
		user:              options.User,
		hostKeyAlgorithms: options.HostKeyAlgorithms,
		clientVersion:     options.ClientVersion,
	}
	if client.user == "" {
		client.user = "root"
	}
	if client.clientVersion == "" {
		client.clientVersion = randomVersion()
	}
	if options.Password != "" {
		client.authMethod = append(client.authMethod, ssh.Password(options.Password))
	}
	if len(options.PrivateKey) > 0 || options.PrivateKeyPath != "" {
		var privateKey []byte
		if len(options.PrivateKey) > 0 {
			privateKey = []byte(strings.Join(options.PrivateKey, "\n"))
		} else {
			var err error
			privateKey, err = filemanager.ReadFile(ctx, os.ExpandEnv(options.PrivateKeyPath))
			if err != nil {
				return nil, E.Cause(err, "read private key")
			}
		}
		var signer ssh.Signer
		var err error
		if options.PrivateKeyPassphrase == "" {
			signer, err = ssh.ParsePrivateKey(privateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(options.PrivateKeyPassphrase))
		}
		if err != nil {
			return nil, E.Cause(err, "parse private key")
		}
		client.authMethod = append(client.authMethod, ssh.PublicKeys(signer))
	}
	for _, hostKey := range options.HostKey {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
		if err != nil {
			return nil, E.Cause(err, "parse host key: ", hostKey)
		}
		client.hostKey = append(client.hostKey, key)
	}
	return client, nil
}

func randomVersion() string {
	version := "SSH-2.0-OpenSSH_"
	if rand.Intn(2) == 0 {
		version += "7." + strconv.Itoa(rand.Intn(10))
	} else {
		version += "8." + strconv.Itoa(rand.Intn(9))
	}
	return version
}

func (s *sshClient) connect(ctx context.Context) (client *ssh.Client, err error) {
	s.clientAccess.Lock()
	defer s.clientAccess.Unlock()

	if s.client != nil {
		s.streams++
		return s.client, nil
	}

	conn, err := s.dialer.DialContext(adapter.ContextForMultiplexSession(ctx), N.NetworkTCP, M.Socksaddr{})
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		handshakeConn := conn
		stopContext := context.AfterFunc(ctx, func() {
			_ = handshakeConn.Close()
		})
		defer func() {
			if !stopContext() {
				s.client = nil
				s.clientConn = nil
				client = nil
				err = ctx.Err()
			}
		}()
	}
	config := &ssh.ClientConfig{
		User:              s.user,
		Auth:              s.authMethod,
		ClientVersion:     s.clientVersion,
		HostKeyAlgorithms: s.hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(s.hostKey) == 0 {
				return nil
			}
			serverKey := key.Marshal()
			for _, hostKey := range s.hostKey {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return E.New("host key mismatch, server send ", key.Type(), " ", base64.StdEncoding.EncodeToString(serverKey))
		},
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, s.serverName, config)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "connect to ssh server")
	}

	client = ssh.NewClient(clientConn, chans, reqs)

	s.clientConn = conn
	s.client = client
	s.streams = 1

	go func() {
		client.Wait()
		conn.Close()
		s.clientAccess.Lock()
		if s.client == client {
			s.client = nil
			s.clientConn = nil
		}
		s.clientAccess.Unlock()
	}()

	return client, nil
}

func (s *sshClient) SetKeepIdleConnections(keep bool) {
	s.clientAccess.Lock()
	s.closeIdle = !keep
	s.clientAccess.Unlock()
	if !keep {
		s.CloseIdleConnections()
	}
}

func (s *sshClient) CloseIdleConnections() {
	s.clientAccess.Lock()
	if s.client == nil || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.client = nil
	s.clientConn = nil
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *sshClient) releaseStream(client *ssh.Client, keepSession bool) {
	s.clientAccess.Lock()
	if s.client != client {
		s.clientAccess.Unlock()
		return
	}
	s.streams--
	if !s.closeIdle || keepSession || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.client = nil
	s.clientConn = nil
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *sshClient) Close() error {
	s.clientAccess.Lock()
	clientConn := s.clientConn
	s.client = nil
	s.clientConn = nil
	s.clientAccess.Unlock()
	return common.Close(clientConn)
}

func (s *sshClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := client.Dial(network, destination.String())
	if err != nil {
		s.releaseStream(client, false)
		return nil, err
	}
	keepSession := adapter.KeepSessionFromContext(ctx)
	return &chanConnWrapper{Conn: conn, onClose: func() { s.releaseStream(client, keepSession) }}, nil
}

func (s *sshClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type chanConnWrapper struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (c *chanConnWrapper) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.onClose)
	return err
}

func (c *chanConnWrapper) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
