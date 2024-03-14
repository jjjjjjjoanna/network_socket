#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

struct ThreadArgs {
    const char *ip;
    int port;
    int server_port;
    int socketfd;
};

int countCharOccurrences(const char *str, char c) {
    int count = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == c) count++;
    }
    return count;
}
//一直接收來自別的客戶的訊息
void* listen_handler(void *args) {
    struct ThreadArgs *thread_args = (struct ThreadArgs *)args;
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket == -1) {
        perror("Error creating listen_socket");
        return NULL;
    }
    struct sockaddr_in listen_address;
    listen_address.sin_family = AF_INET;
    listen_address.sin_port = htons(thread_args->port);
    listen_address.sin_addr.s_addr = inet_addr(thread_args->ip);
    int original_socket = thread_args->socketfd;
    if (bind(listen_socket, (struct sockaddr *)&listen_address, sizeof(listen_address)) == -1) {
        perror("Error binding to listening address");
        close(listen_socket);
        return NULL;
    }
    if (listen(listen_socket, 5) == -1) {
        perror("Error listening for connections");
        close(listen_socket);
        return NULL;
    }
    while (1) {
        struct sockaddr_in client_address;
        socklen_t addr_len = sizeof(client_address);
        int peer_socket = accept(listen_socket, (struct sockaddr *)&client_address, &addr_len);
        if (peer_socket == -1) {
            perror("Error accepting peer connection");
            continue;
        }
        char recvm[80];
        memset(recvm, 0, sizeof(recvm));
        if (recv(peer_socket, recvm, sizeof(recvm), 0) == -1) {
            perror("Error receiving from peer");
            break;
        }
        printf("收到轉帳訊息了!\n");
        send(original_socket, recvm, strlen(recvm), 0);
        close(peer_socket);
    }
    free(args);
    //close(listen_socket);
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 3){
        perror("Invalid command line arguments");
        return 1;
    }
    const char *server_ip = argv[1];
    const int server_port = atoi(argv[2]);
    int client_socket = client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Error creating socket");
        return 1;
    }
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) <= 0) {
        perror("Invalid IP address");
        return 1;
    }
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        perror("Error connecting to the server");
        return 1;
    }
    while (1) {
        printf("Enter a command: ");
        char sendmsg[256];
        fgets(sendmsg, sizeof(sendmsg), stdin);
        size_t len = strlen(sendmsg);
        if (len > 0 && sendmsg[len - 1] == '\n') sendmsg[len - 1] = '\0';
        bool isExit = false ;
        if (strcmp(sendmsg, "Exit") == 0) {//Exit
            if (send(client_socket, sendmsg, strlen(sendmsg) + 1, 0) == -1) {
                perror("Error sending message to server");
                break;
            }
            isExit = true;
        }
        else if (strcmp(sendmsg, "List") == 0) {//List
            if (send(client_socket, sendmsg, strlen(sendmsg) + 1, 0) == -1) {
                perror("Error sending message to server");
                break;
            }
        }
        else if (strstr(sendmsg, "REGISTER") != NULL && countCharOccurrences(sendmsg, '#') == 1) {//REGISTER
            if (send(client_socket, sendmsg, strlen(sendmsg) + 1, 0) == -1) {
                perror("Error sending message to server");
                break;
            }
        }
        else if(countCharOccurrences(sendmsg, '#') == 1){//Login
            if (send(client_socket, sendmsg, strlen(sendmsg) + 1, 0) == -1) {
                perror("Error sending message to server");
                break;
            }
            struct ThreadArgs args;
            char* tt = strtok(sendmsg, "#");
            tt = strtok(NULL, "#");
            args.port = atoi(tt);
            args.ip = server_ip;
            args.server_port = server_port;
            args.socketfd = client_socket;
            pthread_t listen_thread;//看有沒有人要轉帳給我
            if (pthread_create(&listen_thread, NULL, listen_handler, &args) != 0) {
                perror("Error creating listen_thread");
                return 1;
            } 
        }
        else if(countCharOccurrences(sendmsg, '#') == 2){ //A#100#B
            if (send(client_socket, "List\0", 5, 0) == -1) {
                perror("Error sending message to server");
                break;
            }
            char online_list[1000];
            memset(online_list, 0, sizeof(online_list));
            if (recv(client_socket, online_list, sizeof(online_list), 0) == -1) {
                perror("Error receiving online list from server");
                break;
            }
            //printf("received secret list = %s\n", online_list);
            char temp[256];
            strcpy(temp, sendmsg);
            char sender[256];
            int amount;
            char receiver[256];
            sscanf(sendmsg, "%255[^#]#%d#%255s", sender, &amount, receiver);
            printf("the sender is %s, amount is %d, receiver is %s\n", sender, amount, receiver);
            char *tok = strtok(online_list, "#\n");
            int amo = atoi(tok);
            if(amo >= amount){
                tok = strtok(NULL, "#\n");
                char *pk = tok;
                tok = strtok(NULL, "#n\n");//online count
                int cnt = atoi(tok);
                printf("the balance is %d, the pk is %s, the online count is %d\n", amo, pk, cnt);
                for(int i = 0 ; i < cnt ; i++){
                    tok = strtok(NULL, "#\n");
                    char* username = tok;
                    tok = strtok(NULL, "#\n");
                    char* ip_address = tok;
                    tok = strtok(NULL, "#\n");
                    int portNum = atoi(tok);
                    if (strcmp(username, receiver) == 0) {
                        printf("the target is %s, the ip is %s, port is %d\n", username, ip_address, portNum);
                        int targetSocket = socket(AF_INET, SOCK_STREAM, 0);
                        if (targetSocket == -1) {
                            perror("Error creating target socket");
                            return 1;
                        }
                        struct sockaddr_in targetAddress;
                        targetAddress.sin_family = AF_INET;
                        targetAddress.sin_port = htons(portNum);
                        if (inet_pton(AF_INET, ip_address, &targetAddress.sin_addr) <= 0) {
                            perror("Invalid target IP address");
                            return 1;
                        }
                        if (connect(targetSocket, (struct sockaddr *)&targetAddress, sizeof(targetAddress)) == -1) {
                            printf("Fail to connect target client at IP: %s, Port: %d\n", inet_ntoa(targetAddress.sin_addr), ntohs(targetAddress.sin_port));
                            return 1;
                        }
                        else {
                            printf("Connecting to target client at IP: %s, Port: %d\n", inet_ntoa(targetAddress.sin_addr), ntohs(targetAddress.sin_port));
                            printf("the sending payment message is = %s\n", temp);
                            if (send(targetSocket, temp, strlen(temp), 0) == -1) {
                                perror("Error sending message to target client");
                            }
                            close(targetSocket);
                            break;
                        }
                    }
                }
            }
            else{
                printf("yor are so poor!!!\n");
            }
        }
        else{
            printf("Invalid Input!\n");
        }
        char response[1024];
        memset(response, 0, sizeof(response));
        if (recv(client_socket, response, sizeof(response), 0) == -1) {
            perror("Error receiving from server");
            break;
        }
        char *token = strtok(response, "\n");
        while (token != NULL) {
            printf("Received command: %s\n", token);
            token = strtok(NULL, "\n");
        }
        if(isExit) break;
    }
    close(client_socket);
    return 0;
}