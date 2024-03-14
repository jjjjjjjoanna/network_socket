#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAX_USERS 100
#define MAX_THREADS 100


struct ThreadArgs {
    int clientSocketFd;
    const char *clientIpAddress;
    const char* mode;
    char *serverPublicKey;
    char *serverPrivateKey;
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

// 生成 server public, private key
void generateServerKeyPair(char **serverPublicKey, char **serverPrivateKey) {
    RSA *rsa_keypair = RSA_new();
    BIGNUM *e = BN_new();
    int bits = 2048;

    if (!BN_set_word(e, RSA_F4) || !RSA_generate_key_ex(rsa_keypair, bits, e, NULL)) {
        perror("Error generating RSA key pair");
        exit(EXIT_FAILURE);
    }
    BN_free(e);
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa_keypair)) {
        perror("Error writing RSA public key to BIO");
        exit(EXIT_FAILURE);
    }
    long length = BIO_pending(bio);
    *serverPublicKey = (char *)malloc(length + 1);
    if (*serverPublicKey == NULL) {
        perror("Error allocating memory for serverPublicKey");
        exit(EXIT_FAILURE);
    }
    BIO_read(bio, *serverPublicKey, length);
    (*serverPublicKey)[length] = '\0';
    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(bio, rsa_keypair, NULL, NULL, 0, NULL, NULL)) {
        perror("Error writing RSA private key to BIO");
        exit(EXIT_FAILURE);
    }
    length = BIO_pending(bio);
    *serverPrivateKey = (char *)malloc(length + 1);
    if (*serverPrivateKey == NULL) {
        perror("Error allocating memory for serverPrivateKey");
        exit(EXIT_FAILURE);
    }
    BIO_read(bio, *serverPrivateKey, length);
    (*serverPrivateKey)[length] = '\0';
    RSA_free(rsa_keypair);
    BIO_free(bio);
}
//註冊
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
//登入
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

void trimString(char *str) {
    char *start = str;
    while (isspace((unsigned char)*start)) {
        start++;
    }
    if (*start == '\0') {
        return;
    }
    char *end = str + strlen(str) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';
    if (start > str) {
        memmove(str, start, (end - start + 2));
    }
}
// server 使用 client public key 加密
bool encryptAndSend(int socket, const char *message, const char *clientPublicKey) {
    BIO *bio = BIO_new_mem_buf((void *)clientPublicKey, -1);
    if (bio == NULL) {
        perror("Error creating BIO");
        exit(EXIT_FAILURE);
    }
    RSA *rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (rsaPublicKey == NULL) {
        perror("Error reading RSA public key from BIO");
        exit(EXIT_FAILURE);
    }
    BIO_free(bio);
    int messageLength = strlen(message);
    int encryptedSize = RSA_size(rsaPublicKey);
    unsigned char *encryptedMessage = (unsigned char *)malloc(encryptedSize);
    if (encryptedMessage == NULL) {
        perror("Error allocating memory for encryptedMessage");
        exit(EXIT_FAILURE);
        return false;
    }
    int result = RSA_public_encrypt(messageLength, (unsigned char *)message, encryptedMessage, rsaPublicKey, RSA_PKCS1_PADDING);
    if (result == -1) {
        perror("Error encrypting message");
        exit(EXIT_FAILURE);
        return false;
    }
    if (send(socket, encryptedMessage, RSA_size(rsaPublicKey), 0) == -1) {
        perror("Error sending encrypted message to server");
        return false;
    }
    RSA_free(rsaPublicKey);
    free(encryptedMessage);
    return true;
}
//印出表
void printList(int clientSocketFd, int userIndex, const char *mode, int type, char* clientPublicKey) {
    char accountBalance[10];
    memset(accountBalance, 0, sizeof(accountBalance));
    sprintf(accountBalance, "%d", users[userIndex].money);
    
    char messageBuffer[2048];
    memset(messageBuffer, 0, sizeof(messageBuffer));

    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("balance = %d\n", users[userIndex].money);
    }
    sprintf(messageBuffer, "%s\npublic key\n", accountBalance);
    if ((strcmp(mode, "-s") == 0 || strcmp(mode, "-a") == 0) && type == 1) {
        printf("public key\n");
    }
    // Online number
    char online[10];
    memset(online, 0, sizeof(online));
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
            char online_list[100];
            memset(online_list, 0, sizeof(online_list));
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
    if(!encryptAndSend(clientSocketFd, messageBuffer, clientPublicKey)){
        perror("fail to send message!");
        return;
    }
    fflush(stdout);
    return;
}

//找到 index
int checkIndex(char* username){
    for(int i = 0 ; i < userCount ; i++){
        if(strcmp(strtok(users[i].username, " \t\n\r"), strtok(username, " \t\n\r")) == 0)
            return i;
    }
    return -1 ;
}

// 主要程式碼
void *clientHandler(void *args) {
    struct ThreadArgs *threadArgs = (struct ThreadArgs *)args;
    int clientSocketFd = threadArgs->clientSocketFd;
    const char *clientIpAddress = threadArgs->clientIpAddress;
    const char *mode = threadArgs->mode;
    const char *serverPublicKey = threadArgs->serverPublicKey;
    const char *serverPrivateKey = threadArgs->serverPrivateKey;
    free(args);
    int userIndex = -1 ;
    bool isRegistered = false;
    bool isExit = false ;
    //傳送 server public key 給 client
    send(clientSocketFd, serverPublicKey, strlen(serverPublicKey), 0);
    //讀入 server private key
    BIO *privateKeyBio = BIO_new_mem_buf((void *)serverPrivateKey, -1);
    RSA *serverPrivateKeyRSA = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
    BIO_free(privateKeyBio);
    if (!serverPrivateKeyRSA) {
        perror("Error reading RSA private key");
        exit(EXIT_FAILURE);
    }
    //接收目標 client 的 public key
    char clientPublicKey[2048];
    ssize_t bytesRead = recv(clientSocketFd, clientPublicKey, sizeof(clientPublicKey) - 1, 0);
    while(!isExit){
        char before[1024];
        memset(before, 0, sizeof(before));
        //讀指令並且解密
        ssize_t readSomething = recv(clientSocketFd, before, sizeof(before), 0) ;
        char request[2048];
        memset(request, 0, sizeof(request));
        int decryptedBytes = RSA_private_decrypt(readSomething, (const unsigned char *)before,(unsigned char *)request, serverPrivateKeyRSA, RSA_PKCS1_PADDING);

        if( decryptedBytes > 0){
            if(strcmp(mode, "-a") == 0){
                printf("Received data: %s\n", request);
            }
            trimString(request);
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
                        if(!encryptAndSend(clientSocketFd, "100 OK\n", clientPublicKey)){
                            perror("fail to send message!");
                            break;
                        }
                        registerSuccess = true ;
                        isRegistered = true ;
                    }
                }
                token = NULL;
                if(!registerSuccess || userIndex == -1){
                    printf("註冊失敗\n");
                    if(!encryptAndSend(clientSocketFd, "210 FAIL\n", clientPublicKey)){
                        perror("fail to send message!");
                        break;
                    }
                }
            }
            //List
            else if (strcmp(token, "List") == 0) {
                printf(" %s 要清單!\n", users[userIndex].username);
                printList(clientSocketFd, userIndex, mode, 0, clientPublicKey);
            }
            //Exit
            else if(strcmp(token, "Exit") == 0){
                printf(" %s 要登出!\n", users[userIndex].username);
                users[userIndex].online = false ;
                onlineCount -= 1;
                printList(clientSocketFd, userIndex, mode, 1, clientPublicKey);
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
                        printList(clientSocketFd, userIndex, mode, 1, clientPublicKey);
                    }
                    else{
                        if(!encryptAndSend(clientSocketFd, "220 AUTH_FAIL\n", clientPublicKey)){
                            perror("fail to send message!");
                            break;
                        }
                    }
                }
                //transfer
                else {
                    char *usernameB = token;
                    //usernameA 要轉帳 portNumber 元給 usernameB
                    //由usernameB傳送
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
                    printList(clientSocketFd, userIndex, mode, 1, clientPublicKey);
                }
            }
        }
    }
    isExit = false;
    RSA_free(serverPrivateKeyRSA);
    close(clientSocketFd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    if (argc != 3) exit(1);

    int port = atoi(argv[1]);
    const char *mode = argv[2];

    if (strcmp(mode, "-a") != 0 && strcmp(mode, "-d") != 0 && strcmp(mode, "-s") != 0) exit(1);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("socket creation failed");
        exit(1);
    }

    char *serverPublicKey;
    char *serverPrivateKey;

    generateServerKeyPair(&serverPublicKey, &serverPrivateKey);

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
                continue;
            }
            threadArgs->clientSocketFd = clientSocketFd;
            threadArgs->clientIpAddress = inet_ntoa(clientAddr.sin_addr);
            threadArgs->mode = mode;
            threadArgs->serverPublicKey = serverPublicKey;
            threadArgs->serverPrivateKey = serverPrivateKey;

            pthread_create(&threads[threadCount], NULL, clientHandler, (void *)threadArgs);
            threadCount++;
        }
        else {
            close(clientSocketFd);
        }
    }
    free(serverPublicKey);
    free(serverPrivateKey);
    return 0;
}