package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
)

func logInfo(conn net.Conn, username string, password string) {
	fmt.Printf("Username: %s, Password: %s RemoteAddr: %s\n", username, password, conn.RemoteAddr().String())
}
func handlePlainMecanisme(conn net.Conn, credentials string, writer *bufio.Writer) {

	// Decode Base64-encoded credentials
	decodedCreds, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		// Error decoding credentials
		log.Println("Error decoding credentials:", err)
		return
	}

	// Split the decoded credentials into username and password
	creds := strings.SplitN(string(decodedCreds), "\x00", 3)
	if len(creds) != 3 {
		// Invalid credentials format
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

	// Now you have the username and password, you can perform authentication
	// logic based on these credentials
	// For demonstration purposes, we'll print them here
	logInfo(conn, username, password)

	// Send an OK response to indicate successful authentication
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

	// Create a bufio reader and writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Send the welcome message
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
		// Read the command from the client
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading command:", err)
			return
		}

		// Check if the client is authenticated
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

			// Implement authentication logic based on the mechanism and credentials
			// For example, if PLAIN authentication mechanism is used:
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

	// Accept incoming connections and handle them in a separate goroutine
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn)
	}
}
