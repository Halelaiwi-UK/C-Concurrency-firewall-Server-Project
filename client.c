#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

// Set values //
#define BUFFER_SIZE 256

int main(int argc, char *argv[]) {

    if (argc != 4 && argc != 6) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <command>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *command = argv[3];
    if (strcmp(server_ip, "localhost") == 0) {
        server_ip = "127.0.0.1";
    }

    // Create a socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }

    char message[BUFFER_SIZE];
    if (argc == 6) {
        // Full command with IP and port
        snprintf(message, sizeof(message), "%s %s %s", command, argv[4], argv[5]);
    } else {
        // Command only, without IP and port
        snprintf(message, sizeof(message), "%s", command);
    }

    // Set up the server address struct
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    // Convert IP address and set it
    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(client_socket);
        return 1;
    }

    // Connect to the server
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(client_socket);
        return 1;
    }

    // Send the command to the server
    if (send(client_socket, message, strlen(message), 0) == -1) {
        perror("Failed to send command");
        close(client_socket);
        return 1;
    }

    // Receive and display the server’s response
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        perror("Failed to receive response");
    } else if (bytes_received == 0) {
        printf("Server closed the connection.\n");
    } else {
        // Successfull return
        buffer[bytes_received] = '\0';  // Null-terminate the received data
        printf("%s\n", buffer);
    }

    // Close the connection
    close(client_socket);
    return 0;
}
