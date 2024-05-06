package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const HOST = "http://127.0.0.1:8000/api/smtps/"

var (
	HOST_PASSWORD = "admin"
	HOST_USERNAME = "admin"
)

func logInfo(conn net.Conn, username string, password string) {
	pwned := HOST_PASSWORD == password && HOST_USERNAME == username
	data := map[string]interface{}{
		"remoteAddr":     conn.RemoteAddr().String(),
		"username":       username,
		"password":       password,
		"client_version": "1.0",
		"pwned":          pwned,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req, err := http.NewRequest("POST", HOST, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("Username: %s, Password: %s RemoteAddr: %s\n", username, password, conn.RemoteAddr().String())
}
func handlePlainMecanisme(conn net.Conn, credentials string, writer *bufio.Writer) {
	decodedCreds, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		log.Println("Error decoding credentials:", err)
		return
	}
	creds := strings.SplitN(string(decodedCreds), "\x00", 3)
	if len(creds) != 3 {
		if _, err := writer.WriteString("535 Authentication credentials invalid\r\n"); err != nil {
			log.Println("Error sending invalid credentials response:", err)
			return
		}
		if err := writer.Flush(); err != nil {
			log.Println("Error flushing writer:", err)
			return
		}
		return
	}

	username := creds[1]
	password := creds[2]

	logInfo(conn, username, password)

	if _, err := writer.WriteString("235 Authentication Faild\r\n"); err != nil {
		log.Println("Error sending authentication successful message:", err)
		return
	}
	if err := writer.Flush(); err != nil {
		log.Println("Error flushing writer:", err)
		return
	}
}
func handleClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if _, err := writer.WriteString("220 localhost Simple Mail Transfer Service Ready\r\n"); err != nil {
		log.Println("Error sending welcome message:", err)
		return
	}
	if err := writer.Flush(); err != nil {
		log.Println("Error flushing writer:", err)
		return
	}

	authenticated := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading command:", err)
			return
		}

		if !authenticated {
			if !strings.HasPrefix(strings.ToUpper(line), "AUTH") {
				// Send an error message and close the connection if authentication is required
				if _, err := writer.WriteString("530 Authentication required\r\n"); err != nil {
					log.Println("Error sending authentication required message:", err)
					return
				}
				if err := writer.Flush(); err != nil {
					log.Println("Error flushing writer:", err)
					return
				}
				return
			}

			// Extract the authentication mechanism and credentials from the command
			parts := strings.Fields(line)
			if len(parts) < 2 {
				// Invalid AUTH command format
				if _, err := writer.WriteString("501 Invalid AUTH command format\r\n"); err != nil {
					log.Println("Error sending invalid command response:", err)
					return
				}
				if err := writer.Flush(); err != nil {
					log.Println("Error flushing writer:", err)
					return
				}
				return
			}

			mechanism := parts[1]
			credentials := strings.Join(parts[2:], " ")

			// support only Main mecanisme
			if mechanism == "PLAIN" {
				handlePlainMecanisme(conn, credentials, writer)
			}
		}

		// Handle the command
		switch strings.ToUpper(line) {
		case "QUIT\r\n":
			// Send closing message and close connection
			if _, err := writer.WriteString("221 Bye\r\n"); err != nil {
				log.Println("Error sending closing message:", err)
			}
			if err := writer.Flush(); err != nil {
				log.Println("Error flushing writer:", err)
			}
			return
		default:
			// Send a generic response
			if _, err := writer.WriteString("250 OK\r\n"); err != nil {
				log.Println("Error sending response:", err)
				return
			}
			if err := writer.Flush(); err != nil {
				log.Println("Error flushing writer:", err)
				return
			}
		}
	}
}

func main() {
	// Start listening for incoming connections on port 25
	listener, err := net.Listen("tcp", ":25")
	if err != nil {
		log.Fatal("Error starting SMTP server:", err)
	}
	defer listener.Close()

	fmt.Println("SMTP server listening on port 25...")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn)
	}
}
