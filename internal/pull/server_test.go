package pull

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/feauche/nodeservice-agent/internal/state"
)

func TestCertificateStableAndUnique(t *testing.T) {
	a, err := EnsureCertificate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b, err := EnsureCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EnsureCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different agents received the same TLS certificate")
	}
	if b != again {
		t.Fatal("certificate changed during repeated configuration")
	}
}

func TestCertificateRepairsBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CertFile), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCertificate(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)); err != nil {
		t.Fatalf("repaired pair is invalid: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCertificate(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)); err != nil {
		t.Fatalf("pair with repaired key is invalid: %v", err)
	}
}

func TestRunRequiresKeyAndServesSnapshot(t *testing.T) {
	dir := t.TempDir()
	certB64, err := EnsureCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if port < 10000 { // An ephemeral port should be five-digit on supported Linux/macOS systems.
		t.Skip("ephemeral port is outside the agent range")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			State:    &state.PullState{Port: port, AccessKey: "test-key-that-is-longer-than-32-bytes", ServerID: "s1", ServerName: "test"},
			StateDir: dir,
			Version:  "v0.8.0",
			Log:      zerolog.New(io.Discard),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
	})

	der, _ := base64.StdEncoding.DecodeString(certB64)
	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, ServerName: "nodeservice-agent", MinVersion: tls.VersionTLS13,
	}}}
	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/v1/snapshot?metrics=0"
	var res *http.Response
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer test-key-that-is-longer-than-32-bytes")
		res, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "{\"serverId\":\"s1\",\"version\":\"v0.8.0\"}\n" {
		t.Fatalf("body = %s", body)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer wrong-key-that-is-longer-than-32-bytes")
	denied, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key status = %d", denied.StatusCode)
	}
}
