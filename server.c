#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#define MAX_USERS 100
#define MAX_THREADS 100

struct ThreadArgs {
    int clientSocketFd;
    const char *clientIpAddress;
    const char* mode;
};

struct User {
    char username[50];
    int port;
    int money;
    char ip_address[25];
    bool online;
};

struct User users[MAX_USERS];
int userCount = 0; //總共有註冊過的人數
int onlineCount = 0 ;//上線中人數

int registerUser(const char *username, const char* clientIpAddress) {
    if (userCount >= MAX_USERS) return false ;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0) {
            printf("已經有人註冊過這個使用者名稱了\n");
            return -1;
        }
    }
    strcpy(users[userCount].username, username);
    strcpy(users[userCount].ip_address, clientIpAddress);
    users[userCount].port = -1;
    users[userCount].money = 10000;
    users[userCount].online = false;
    userCount++;
    printf("成功註冊！\n");
    return userCount;
}

int loginUser(char*username, const int port){
    for (int i = 0; i < userCount; i++) {
        if (strcmp(strtok(users[i].username, " \t\n\r"), strtok(username, " \t\n\r")) == 0) {
            users[i].port = port;
            if(users[i].online){
                printf("你已經登入啦!\n");
                return i ;
            }
            users[i].online = true;
            onlineCount += 1;
            return i;
        }
    }
    return -1 ;
}

void printList(int clientSocketFd, int userIndex, const char *mode, int type) {
    char accountBalance[10];
    sprintf(accountBalance, "%d", users[userIndex].money);
    
    char messageBuffer[2048];

    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("balance = %d\n", users[userIndex].money);
    }
    
    sprintf(messageBuffer, "%s\npublic key\n", accountBalance);

    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("public key\n");
    }

    // Online number
    char online[10];
    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("online count = %d\n", onlineCount);
    }
    sprintf(online, "%d", onlineCount);
    sprintf(messageBuffer + strlen(messageBuffer), "%s\n", online);

    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("online users:\n");
    }

    // Online list
    int now = 0;
    for (int i = 0; i < userCount; i++) {
        if (users[i].online) {
            now += 1;
            char online_list[1000];
            sprintf(online_list, "%s#%s#%d\n", users[i].username, users[i].ip_address, users[i].port);
            sprintf(messageBuffer + strlen(messageBuffer), "%s", online_list);

            if (now == onlineCount) {
                online_list[sizeof(online_list) - 1] = '\0';
            }

            if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
                printf("online users = %s#%s#%d\n", users[i].username, users[i].ip_address, users[i].port);
            }
        }
    }
    send(clientSocketFd, messageBuffer, strlen(messageBuffer), 0);
    fflush(stdout);
    return;
}

int checkIndex(char* username){ //to know who are transfering
    for(int i = 0 ; i < userCount ; i++){
        if(strcmp(strtok(users[i].username, " \t\n\r"), strtok(username, " \t\n\r")) == 0)
            return i;
    }
    return -1 ;
}

void *clientHandler(void *args) {
    struct ThreadArgs *threadArgs = (struct ThreadArgs *)args;
    int clientSocketFd = threadArgs->clientSocketFd;
    const char *clientIpAddress = threadArgs->clientIpAddress;
    const char *mode = threadArgs->mode;
    free(args);
    int userIndex = -1 ;
    bool isRegistered = false;
    bool isExit = false ;

    while(!isExit){
        char request[1024];
        memset(request, 0, sizeof(request));
        ssize_t readSomething = recv(clientSocketFd, request, sizeof(request), 0) ;
        if( readSomething > 0){
            if(strcmp(mode, "-a") == 0){
                printf("Received data: %s\n", request);
            }
            char *token = strtok(request, "#");
            //REGISTER
            if (strcmp(token, "REGISTER") == 0) {
                bool registerSuccess = false;
                token = strtok(NULL, "#");
                printf("有個叫 %s 的要註冊\n", token);
                if (token != NULL) {
                    char *username = token;
                    userIndex = registerUser(username, clientIpAddress);
                    if(userIndex != -1){
                        send(clientSocketFd, "100 OK\n", 7, 0);
                        registerSuccess = true ;
                        isRegistered = true ;
                    }
                }
                token = NULL;
                if(!registerSuccess || userIndex == -1){
                    printf("註冊失敗\n");
                    send(clientSocketFd, "210 FAIL\n", 9, 0);
                }
            }
            else if(isRegistered){
                //List
                if (strcmp(token, "List") == 0) {
                    printf(" %s 要清單!\n", users[userIndex].username);
                    printList(clientSocketFd, userIndex, mode, 0);
                }
                //Exit
                else if(strcmp(token, "Exit") == 0){
                    printf(" %s 要登出!\n", users[userIndex].username);
                    users[userIndex].online = false ;
                    onlineCount -= 1;
                    printList(clientSocketFd, userIndex, mode, 1);
                    printf("Bye\n");
                    isExit = true ;
                    break;
                }
                else{
                    //Login
                    char *usernameA = token;
                    token = strtok(NULL, "#");
                    int portNumber = atoi(token);//轉帳金額或者是portnumber
                    token = strtok(NULL, "#");
                    if(token == NULL){
                        printf("有個叫 %s 的要登入\n", usernameA);
                        userIndex = loginUser(usernameA, portNumber);
                        if(userIndex != -1){
                            printList(clientSocketFd, userIndex, mode, 1);
                        }
                        else{
                            send(clientSocketFd, "220 AUTH_FAIL\n", 14, 0);
                        }
                    }
                    //transfer
                    else {
                        char *usernameB = token;
                        //usernameA 要轉帳 portNumber 元給 usernameB
                        //由usernameB傳送
                        printf("有人要轉帳\n");
                        printf("%s 轉給 %s, %d 元\n", usernameA, usernameB, portNumber);
                        int userA = checkIndex(usernameA);
                        int userB = checkIndex(usernameB);
                        if(userB == userIndex && userA != -1){
                            users[userB].money += portNumber;
                            users[userA].money -= portNumber;
                            printf("money update finish!!!\n");
                        }
                        else{
                            printf("wrong send message\n");
                        } 
                        printList(clientSocketFd, userIndex, mode, 1);
                    }
                }
            }
            else {
            send(clientSocketFd, "Please register first\n", 22, 0);
            }
        }
    }
    isExit = false;
    close(clientSocketFd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 3) exit(1);

    int port = atoi(argv[1]);
    const char *mode = argv[2];

    if (strcmp(mode, "-a") != 0 && strcmp(mode, "-d") != 0 && strcmp(mode, "-s") != 0) exit(1);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("socket creation failed");
        exit(1);
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind failed");
        exit(1);
    }
    if (listen(serverSocket, 5) < 0) {
        perror("listen failed");
        exit(1);
    }

    pthread_t threads[MAX_THREADS];
    int threadCount = 0;

    while (1) {
        int clientSocketFd;
        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        clientSocketFd = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLen);
        if (threadCount < MAX_THREADS) {
            struct ThreadArgs *threadArgs = (struct ThreadArgs *)malloc(sizeof(struct ThreadArgs));
            if (threadArgs == NULL) {
                perror("malloc failed");
                close(clientSocketFd);
                continue; // 继续等待下一个连接
            }
            threadArgs->clientSocketFd = clientSocketFd;
            threadArgs->clientIpAddress = inet_ntoa(clientAddr.sin_addr);
            threadArgs->mode = mode;

            pthread_create(&threads[threadCount], NULL, clientHandler, (void *)threadArgs);
            threadCount++;
        }
        else {
            close(clientSocketFd);
        }
    }
    return 0;
}

