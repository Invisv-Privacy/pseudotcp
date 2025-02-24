package testutils

import (
	"io"
	"path"
	"path/filepath"
	"runtime"

	masqueH2 "github.com/invisv-privacy/masque/http2"
)

type ProxyClient struct {
	*masqueH2.Client
	ProxyIP string
}

func (p *ProxyClient) Close() error {
	return nil
}

func (p *ProxyClient) Connect() error {
	return p.Client.ConnectToProxy()
}

func (p *ProxyClient) CurrentProxyIP() string {
	return p.ProxyIP
}

func (p *ProxyClient) CreateTCPStream(addr string) (io.ReadWriteCloser, error) {
	return p.Client.CreateTCPStream(addr)
}

func (p *ProxyClient) CreateUDPStream(addr string) (io.ReadWriteCloser, error) {
	return p.Client.CreateUDPStream(addr)
}

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(path.Dir(b)))
	return filepath.Dir(d)
}
