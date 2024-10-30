#include <inttypes.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Set values //
#define BUFFER_SIZE 256
#define MAX_IP_VALUE 255
#define MAX_PORT_VALUE 65535

// Structs declarations //
typedef struct linkedlist {
    char ip[BUFFER_SIZE];
    char port[BUFFER_SIZE];
    struct linkedlist *next;
    struct linkedlist *linkedData;
} linkedlist;

typedef struct threadargs {
    int client_socket;
    char input[BUFFER_SIZE];
} threadargs;

// function prototypes //
// List read/manipulation functions
linkedlist *tailOfList(linkedlist **head);
linkedlist *create_node(const char *ip, const char *port);
int isInList(linkedlist **head, const char *ip, const char *port);
int addIPToRule(linkedlist *head, const char *ip, const char *port);
int deleteRule(linkedlist **head, const char *ip, const char *port, int client_socket);
void freeLinkedList(linkedlist **list);
void deleteData(linkedlist *node);
void add_rule(linkedlist **list, const char *ip, const char *port);
void add_to_rule(linkedlist **list, const char *ip, const char *port);
void add_to_requests(linkedlist **list, const char *input);
// Main program functions
int connectUser(linkedlist **rules,char *ip, char *port, int client_socket);
char** get_input(linkedlist **requestsList, int client_socket);
void *process_requests(void *args);
// validity functions
unsigned int ip_to_int(const char *ip);
int is_within_port_range(const char *port_range, const char *port);
int is_within_ip_range(const char *ip, const char *ip_range);
int is_valid_port(const char *port);
int is_valid_port_range(const char *port);
int is_valid_ip_octets(int ip_octet[4]);
int is_valid_ip(const char *ip);
int is_valid_ip_range(const char *ip_range);
int checkValidity(const char *ip_range, const char *port_range);
//Printing functions
void returnData(linkedlist **rule, int client_socket);
void list_requests(linkedlist **requests, int client_socket);
void returnQueries(linkedlist **rules, int client_socket);
void send_or_print(char *message, int client_socket);

// Global variables //
int is_interactive = 1;
linkedlist *requests = NULL;
linkedlist *rules = NULL;
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t requests_mutex = PTHREAD_MUTEX_INITIALIZER;

// Start of code //
linkedlist *tailOfList(linkedlist **head) {
    if (*head == NULL) {
        return NULL;
    }

    linkedlist *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    return current;
}

void send_or_print(char *messageptr, int client_socket) {
    // Duplicate the input message to make it writable as input pointers are read only
    size_t length = strlen(messageptr);
    char *message = malloc(length + 2);  // +2 for newline and null terminator
    if (message == NULL) {
        perror("Failed to allocate memory for message");
        return;
    }
    strcpy(message, messageptr);  // Copy the input message to the writable buffer

    if (is_interactive) {
        // Print to terminal if interactive
        printf("%s\n", message);
    } else {
        // Check if client socket is valid before sending
        if (client_socket >= 0) {
             // Send message in chunks until the entire message is sent
            ssize_t total_bytes_sent = 0;
            strcat(message, "\n");  // add new line at end
            ssize_t message_length = strlen(message);
            while (total_bytes_sent < message_length) {
                ssize_t bytes_sent = send(client_socket, message + total_bytes_sent, message_length - total_bytes_sent, 0);
                if (bytes_sent == -1) {
                    perror("Error sending message to client, check if server is open");
                    break;
                }
                total_bytes_sent += bytes_sent;
            }
        } else {
            fprintf(stderr, "Error: No valid client socket and not in interactive mode.\n");
        }
    }
}

linkedlist *create_node(const char *ip, const char *port) {
    linkedlist *newNode = malloc(sizeof(linkedlist));
    if (port == NULL) {
        port = "\0";
    }
    if (ip == NULL) {
        ip = "\0";
    }
    strcpy(newNode->ip, ip);
    strcpy(newNode->port, port);
    newNode->next = NULL;
    newNode->linkedData = NULL;
    return newNode;
}
// Something I found off the internet, its basically converting the ip from a 4 octets into 1 big integer
unsigned int ip_to_int(const char *ip) {
    unsigned int a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int is_within_ip_range(const char *ip, const char *ip_range) {
    // Copy the input string to a mutable array because strtok modifies the string
    char buffer[BUFFER_SIZE];
    strncpy(buffer, ip_range, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Split the string by the delimiter "-"
    char *start_ip = strtok(buffer, "-");
    char *end_ip = strtok(NULL, "-");
    unsigned int ip_val = ip_to_int(ip);
    unsigned int start_ip_val = ip_to_int(start_ip);
    unsigned int end_ip_val = ip_to_int(end_ip);

    return ip_val >= start_ip_val && ip_val <= end_ip_val;
}

int is_within_port_range(const char *port_range, const char *port) {
    // Copy the input string to a mutable array because strtok modifies the string
    char buffer[BUFFER_SIZE];
    strncpy(buffer, port_range, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Split the string by the delimiter "-"
    char *port1 = strtok(buffer, "-");
    char *port2 = strtok(NULL, "-");
    // convert to int
    long int port_start = strtol(port1, NULL, 0);
    long int port_end = strtol(port2, NULL, 0);
    long int lport = strtol(port, NULL, 0);

    return port_start <= lport && lport <= port_end;
}

int isInList(linkedlist **head, const char *ip, const char *port) {
    linkedlist *current = *head;
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) {
            if (strcmp(current->port, port) == 0) {
                return 1;
            }
        }
        current = current->next;
    }
    return 0;
}
int addIPToRule(linkedlist *head, const char *ip, const char *port) {
    linkedlist *current = head;
    while (current != NULL) {
        int within_ip = 0;
        int within_port = 0;
        char *ip_range = current->ip;
        char *port_range = current->port;
        // Check if the ip and port are within this rule
        if (strchr(port_range, '-') != NULL) {
            within_port = is_within_port_range(port_range, port);
        } else {
            long int lport = strtol(port, NULL, 0);
            long int lport_rule = strtol(port_range, NULL, 0);
            within_port = lport == lport_rule;
        }

        if (strchr(ip_range, '-') != NULL) {
            within_ip = is_within_ip_range(ip, ip_range);
        } else {
            unsigned int ip_val = ip_to_int(ip);
            unsigned int rule_ip_val = ip_to_int(ip_range);
            within_ip = ip_val == rule_ip_val;
        }

        if (within_port && within_ip) {
            if (isInList(&head->linkedData, ip, port)) {
                within_ip = 0;
                within_port = 0;
                current = current->next;
                continue;
            }
            // No need to mutex lock, already inside of function
            add_to_rule(&current, ip, port);
            return 1;
        }
        current = current->next;
    }
    return 0;
}
void add_to_rule(linkedlist **list, const char *ip, const char *port) {
    pthread_mutex_lock(&rules_mutex);
    linkedlist *newNode = create_node(ip, port);
    if ((*list)->linkedData == NULL) {
        (*list)->linkedData = newNode;
    } else {
        tailOfList(&((*list)->linkedData))->next = newNode;
    }
    pthread_mutex_unlock(&rules_mutex);
}

void freeLinkedList(linkedlist **list) {
    // Lock everything
    pthread_mutex_lock(&rules_mutex);
    pthread_mutex_lock(&requests_mutex);
    linkedlist *head = *list;
    while (head != NULL) {
        linkedlist *next = head->next;
        deleteData(head);
        free(head);
        head = next;
    }
    *list = NULL;
    // Unlock
    pthread_mutex_unlock(&rules_mutex);
    pthread_mutex_unlock(&requests_mutex);
}

// to free the data attached to the node
void deleteData(linkedlist *node) {
    if (node == NULL || node->linkedData == NULL) return;

    linkedlist *head = node->linkedData;
    while (head != NULL) {
        linkedlist *next = head->next;
        free(head);
        head = next;
    }
    node->linkedData = NULL;  // Set linkedData to NULL after freeing
}

void add_to_requests(linkedlist **list, const char *input) {
    // Lock as its a shared resource
    pthread_mutex_lock(&requests_mutex);
    linkedlist *newNode = create_node(input, NULL);
    if (*list == NULL) {
        *list = newNode;
    } else {
        // Go to end, and append
        tailOfList(list)->next = newNode;
    }
    // make sure to unlock
    pthread_mutex_unlock(&requests_mutex);
}

void add_rule(linkedlist **list, const char *ip, const char *port) {
    // Lock as its a shared resource
    pthread_mutex_lock(&rules_mutex);
    linkedlist *newNode = create_node(ip, port);
    if (*list == NULL) {
        *list = newNode;
    } else {
        // Go to end, and append
        tailOfList(list)->next = newNode;
    }
    // make sure to unlock
    pthread_mutex_unlock(&rules_mutex);
}

char** get_input(linkedlist **requestsList, int client_socket) {
    // input is split into 3 strings
    // Its freed in the main function
    char **string_array = malloc(3 * sizeof(char*));
    string_array[0] = string_array[1] = string_array[2] = NULL;
    if (is_interactive) {
        char buffer[BUFFER_SIZE];

        // Take input from terminal
        fgets(buffer, BUFFER_SIZE, stdin);

        // Remove newline character from fgets
        buffer[strcspn(buffer, "\n")] = '\0';
        add_to_requests(requestsList, buffer);


        char *token = strtok(buffer, " ");
        string_array[0] = token ? strdup(token) : strdup("");

        token = strtok(NULL, " ");
        string_array[1] = token ? strdup(token) : strdup("");

        token = strtok(NULL, " ");
        string_array[2] = token ? strdup(token) : strdup("");
    }
    return string_array;
}

int is_valid_port(const char *port) {
    char *end;
    long int lport = strtol(port, &end, 10);

    // Check if any non-numeric characters were encountered or if the value is out of range
    if (*end != '\0' || lport > MAX_PORT_VALUE || lport < 0) {
        return 0;  // Invalid port
    }
    return lport <= MAX_PORT_VALUE && lport >= 0;
}

int is_valid_port_range(const char *port) {
    // Copy the input string to a mutable array because strtok modifies the string
    char buffer[BUFFER_SIZE];
    strncpy(buffer, port, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Split the string by the delimiter "-"
    char *port1 = strtok(buffer, "-");
    char *port2 = strtok(NULL, "-");

    if (strtol(port1, NULL, 0) > strtol(port2, NULL, 0)) {
        return 0;
    }

    return is_valid_port(port1) && is_valid_port(port2);
}
int is_valid_ip_octets(int ip_octet[4]) {
    // check each octet value
    for (int i = 0; i < 4; i++) {
        if (ip_octet[i] > MAX_IP_VALUE || ip_octet[i] < 0) {
            return 0;
        }
    }
    return 1;
}
int is_valid_ip(const char *ip) {
    // Copy the input string to a mutable array because strtok modifies the string
    char buffer[BUFFER_SIZE];
    strncpy(buffer, ip, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Split the string by the delimiter "-"
    int octets[4];
    // Split the ips
    sscanf(buffer, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    return is_valid_ip_octets(octets);
}
int is_valid_ip_range(const char *ip_range) {
    // Copy the input string to a mutable array because strtok modifies the string
    char buffer[BUFFER_SIZE];
    strncpy(buffer, ip_range, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Split the string by the delimiter "-"
    char *ip1 = strtok(buffer, "-");
    char *ip2 = strtok(NULL, "-");

    if (!(is_valid_ip(ip1) && is_valid_ip(ip2))) {
        return 0;
    }
    int octets_ip1[4], octets_ip2[4];
    // Split the ips
    sscanf(ip1, "%d.%d.%d.%d", &octets_ip1[0], &octets_ip1[1], &octets_ip1[2], &octets_ip1[3]);
    sscanf(ip2, "%d.%d.%d.%d", &octets_ip2[0], &octets_ip2[1], &octets_ip2[2], &octets_ip2[3]);
    for (int i = 0; i < 4; i++) {
        if (octets_ip1[i] <= octets_ip2[i]) {
            continue;
        }
        if (octets_ip1[i] > octets_ip2[i]) {
            return 0;  // ip1 is greater than ip2
        }
    }

    return 1;
}

int checkValidity(const char *ip_range, const char *port_range) {
    // Null check
    if (ip_range == NULL || port_range == NULL || strcmp(ip_range, "") == 0 || strcmp(port_range, "") == 0){
        return 0;
    }
    int validPort = 0;
    int validIp = 0;
    // check port first
    if (strchr(port_range, '-') != NULL) {
        validPort = is_valid_port_range(port_range);
    } else {
        validPort = is_valid_port(port_range);
    }
    // check ip
    if (strchr(ip_range, '-') != NULL) {
        validIp = is_valid_ip_range(ip_range);
    } else {
        validIp = is_valid_ip(ip_range);
    }
    return validIp && validPort;
}

void list_requests(linkedlist **requests, int client_socket) {
    // Print each request, the request is stored in the ip
    linkedlist *head = *requests;
    while (head != NULL) {
        send_or_print(head->ip, client_socket);
        head = head->next;
    }
}
void returnData(linkedlist **rule, int client_socket) {
    linkedlist *head = (*rule)->linkedData;
    while (head != NULL) {
        char message[BUFFER_SIZE * 3];
        snprintf(message, BUFFER_SIZE*3, "Query: %s %s", head->ip, head->port);
        send_or_print(message, client_socket);
        head = head->next;
    }
}

void returnQueries(linkedlist **rules, int client_socket) {
    // Iterate and print all linked data
    linkedlist *rule_list = *rules;
    while (rule_list != NULL) {
        char message[BUFFER_SIZE * 3];
        snprintf(message, BUFFER_SIZE*3, "Rule: %s %s", rule_list->ip, rule_list->port);
        send_or_print(message, client_socket);
        returnData(&rule_list, client_socket);
        rule_list = rule_list->next;
    }
}
int connectUser(linkedlist **rules,char *ip, char *port, int client_socket) {
    // if invalid
    if (!checkValidity(ip, port)) {
        send_or_print("Illegal IP address or port specified.", client_socket);
        return 0;
    }
    int added = addIPToRule(*rules, ip, port);
    if (added) {
        send_or_print("Connection accepted.", client_socket);
    }
    else {
        send_or_print("Connection rejected.", client_socket);
    }
    return added;
}

int deleteRule(linkedlist **head, const char *ip, const char *port, int client_socket) {
    // Lock as rules are a shared resource
    pthread_mutex_lock(&rules_mutex);
    // Check validity and null ptr before continuing
    if (!checkValidity(ip, port)) {
        send_or_print("Rule invalid.", client_socket);
        pthread_mutex_unlock(&rules_mutex);
        return 0;
    }
    if (head == NULL || *head == NULL) {
        send_or_print("Rule not found.", client_socket);
        pthread_mutex_unlock(&rules_mutex);
        return 0;
    }

    linkedlist *current = *head;
    linkedlist *previous = NULL;

    // Travel through list to search for the rule and delete when found
    while (current != NULL) {
        int ip_match = strcmp(current->ip, ip) == 0;
        int port_match = strcmp(current->port, port) == 0;

        if (ip_match && port_match) {
            if (previous == NULL) {
                *head = current->next;
            } else {
                previous->next = current->next;
            }
            // Delete the data attached to the rule
            deleteData(current);
            free(current);
            send_or_print("Rule deleted", client_socket);
            // Make sure to unlock before returning
            pthread_mutex_unlock(&rules_mutex);
            return 1;
        }
        previous = current;
        current = current->next;
    }
    // If not found
    send_or_print("Rule not found", client_socket);
    // Make sure to unlock before returning
    pthread_mutex_unlock(&rules_mutex);
    return 0;
}
void *process_requests(void *args) {
    // Get thread args if theres any
    threadargs *targs = (threadargs *)args;
    int client_socket = targs->client_socket;
    // Read input
    char **inputArray;

    if(is_interactive){
        // Interactive version
        inputArray = get_input(&requests, client_socket);
    }
    else{
        // Non-interactive version
        // Get the input from the thread and tokenize it
        char **string_array = malloc(3 * sizeof(char*));
        string_array[0] = string_array[1] = string_array[2] = NULL;

        char *input = targs->input;
        add_to_requests(&requests, input);
        char *token = strtok(input, " ");
        string_array[0] = token ? strdup(token) : strdup("");

        token = strtok(NULL, " ");
        string_array[1] = token ? strdup(token) : strdup("");

        token = strtok(NULL, " ");
        string_array[2] = token ? strdup(token) : strdup("");
        inputArray = string_array;
    }

    // split the input

    char *input =  inputArray[0];;
    char *ip_range = inputArray[1];
    char *port_range = inputArray[2];

    // handle the command input
    if (input[0] == 'A') {
        int valid = checkValidity(ip_range, port_range);
        if (valid == 0) {
            send_or_print("Invalid rule", client_socket);
        }
        else {
            add_rule(&rules, ip_range, port_range);
            send_or_print("Rule added", client_socket);
        }

    } else if (input[0] == 'R') {
        list_requests(&requests, client_socket);
    }
    else if (input[0] == 'C') {
        connectUser(&rules, ip_range, port_range, client_socket);
    }
    else if (input[0] == 'D') {
        deleteRule(&rules, ip_range, port_range, client_socket);
    }
    else if (input[0] == 'L') {
        returnQueries(&rules, client_socket);
    }
    else if (input[0] == 'E' || input[0] == '\0') {
        // Free the lists since we are not storing them nor are they accessed afterward
        freeLinkedList(&rules);
        freeLinkedList(&requests);
        for (int i = 0; i < 3; ++i) {
            free(inputArray[i]);
        }
        free(inputArray);
        // Set pointers to null to protect against malicious injections
        rules = NULL;
        requests = NULL;
        inputArray = NULL;
        return (void *) 1;
    } else {
        send_or_print("Illegal request\n", client_socket);
    }

    // Free inputArray after each command to clean up
    for (int i = 0; i < 3; ++i) {
        free(inputArray[i]);
    }
    free(inputArray);

    return (void *) 0;
}

void *client_handler(void *args) {
    // get the thread input
    threadargs *targs = (threadargs *)args;
    int client_socket = targs->client_socket;

    while (1) {
        // Clear the input buffer
        memset(targs->input, 0, BUFFER_SIZE);

        // Receive data from the client
        ssize_t bytes_received = recv(client_socket, targs->input, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Client disconnected.\n");
            } else {
                perror("recv failed");
            }
            break;
        }

        // Null-terminate the received data
        targs->input[bytes_received] = '\0';
        printf("Received input from client: %s\n", targs->input);

        // Pass received data to process_requests for handling
        process_requests(targs);
    }

    // Close the client socket and free threadargs
    close(client_socket);
    free(targs);

    return NULL;
}


int main (int argc, char *argv[]){
    // Interactive version
    if (argc == 2 && strcmp(argv[1], "-i") == 0) {
        // Set the interactive flag to true, helps other functions
        is_interactive = 1;
        // Placeholder
        threadargs *args = malloc(sizeof(threadargs));
        args->client_socket = -1;
        // Interactive loop
        while (1){
            // cast from void * to int
            int exit = (int)(intptr_t) process_requests(args);
            if (exit){
                break;
            }
        }
        free(args);
    }
    else if (argc == 2 && is_valid_port(argv[1])) {
        // Set the interactive flag to false, helps other functions
        is_interactive = 0;

        // Server variables
        int server_socket, client_socket;
        int port = atoi(argv[1]);
        // We don't declare this as pointers so we just let the compiler handle the memory allocation
        struct sockaddr_in server_addr, client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Set up the server socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);

        if (server_socket == -1) {
            perror("Failed to create socket");
            return 0;
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        // Bind the socket to the port
        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Bind failed");
            close(server_socket);
            return 1;
        }

        // Listen for incoming connections
        printf("Server started!\n");
        if (listen(server_socket, 5) < 0) {
            perror("Listen failed");
            close(server_socket);
            return 1;
        }
        // Server loop
        while (1) {
            // accept any incoming client
            client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client_socket < 0) {
                perror("Failed to accept client connection");
                continue;
            }

            // iniatlize pointer to store client input and client id
            threadargs *args = malloc(sizeof(threadargs));
            args->client_socket = client_socket;

            // Create thread for client and run the client_handler function in that thread
            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, client_handler, (void *)args) != 0) {
                perror("Failed to create thread");
                close(client_socket);
                free(args);
                continue;
            }

            // Detach the thread so that resources are freed when the thread terminates
            pthread_detach(thread_id);
        }

        close(server_socket);

    }
    else {
        perror("invalid startup arguments.");
    }
    return 0;
}