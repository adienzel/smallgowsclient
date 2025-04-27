package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"os"
)

//func main() {
//	// Load client certificate and key
//	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
//	if err != nil {
//		log.Fatalf("Failed to load client certificate and key: %v", err)
//	}
//
//	// Load CA certificate
//	caCert, err := os.ReadFile("ca.crt")
//	if err != nil {
//		log.Fatalf("Failed to read CA certificate: %v", err)
//	}
//	caCertPool := x509.NewCertPool()
//	caCertPool.AppendCertsFromPEM(caCert)
//
//	// Set up TLS configuration
//	tlsConfig := &tls.Config{
//		Certificates: []tls.Certificate{cert},
//		RootCAs:      caCertPool,
//	}
//
//	// Create WebSocket dialer with TLS configuration
//	dialer := websocket.Dialer{
//		TLSClientConfig: tlsConfig,
//	}
//
//	// Connect to WebSocket server
//	url := "wss://localhost/ws/VIN1234567890"
//	header := http.Header{}
//	conn, _, err := dialer.Dial(url, header)
//	if err != nil {
//		log.Fatalf("Failed to connect to WebSocket server: %v", err)
//	}
//	defer conn.Close()
//
//	// Send a message
//	message := "Hello, WebSocket server!"
//	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
//	if err != nil {
//		log.Fatalf("Failed to send message: %v", err)
//	}
//
//	// Read a message
//	_, response, err := conn.ReadMessage()
//	if err != nil {
//		log.Fatalf("Failed to read message: %v", err)
//	}
//	fmt.Printf("Received: %s\n", response)
//}

func loadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("os.ReadFile(certFile): %v", err)
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("os.ReadFile(keyFile): %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEMBlock)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509.ParsePKCS1PrivateKey: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certPEMBlock},
		PrivateKey:  key,
	}

	return cert, nil
}

func main() {
	// Load client certificate and key
	cert, err := loadKeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatalf("Failed to load client certificate and key: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Create WebSocket dialer with TLS configuration
	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	// Connect to WebSocket server
	url := "wss://example.com/ws"
	header := http.Header{}
	conn, _, err := dialer.Dial(url, header)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer conn.Close()

	// Send a message
	message := "Hello, WebSocket server!"
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		log.Fatalf("Failed to send message: %v", err)
	}

	// Read a message
	_, response, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}
	fmt.Printf("Received: %s\n", response)
}
