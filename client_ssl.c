#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct ThreadArgs {
    const char *ip;
    int port;
    int server_port;
    int socketfd;
    char *serverPublicKey;
};

int countCharOccurrences(const char *str, char c) {
    int count = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == c) count++;
    }
    return count;
}

//生成 client 公鑰和私鑰
void generateClientKeyPair(char **clientPublicKey, char **clientPrivateKey) {
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
    *clientPublicKey = (char *)malloc(length + 1);
    if (*clientPublicKey == NULL) {
        perror("Error allocating memory for serverPublicKey");
        exit(EXIT_FAILURE);
    }
    BIO_read(bio, *clientPublicKey, length);
    (*clientPublicKey)[length] = '\0';
    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(bio, rsa_keypair, NULL, NULL, 0, NULL, NULL)) {
        perror("Error writing RSA private key to BIO");
        exit(EXIT_FAILURE);
    }
    length = BIO_pending(bio);
    *clientPrivateKey = (char *)malloc(length + 1);
    if (*clientPrivateKey == NULL) {
        perror("Error allocating memory for serverPrivateKey");
        exit(EXIT_FAILURE);
    }
    BIO_read(bio, *clientPrivateKey, length);
    (*clientPrivateKey)[length] = '\0';
    RSA_free(rsa_keypair);
    BIO_free(bio);
}

bool encryptAndSend(int socket, const char *message, const char *somePublicKey) {
    // 使用 server 或 peer 的公鑰進行加密
    BIO *bio = BIO_new_mem_buf((void *)somePublicKey, -1);
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
    char* serverPublicKey = thread_args->serverPublicKey;
    char *peerPublicKey;
    char *peerPrivateKey;

    generateClientKeyPair(&peerPublicKey, &peerPrivateKey);

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
        BIO *peerprivateKeyBio = BIO_new_mem_buf((void *)peerPrivateKey, -1);
        RSA *peerPrivateKeyRSA = PEM_read_bio_RSAPrivateKey(peerprivateKeyBio, NULL, NULL, NULL);
        BIO_free(peerprivateKeyBio);
        if (!peerPrivateKeyRSA) {
            perror("Error reading RSA private key");
            exit(EXIT_FAILURE);
        }
        send(peer_socket, peerPublicKey, strlen(peerPublicKey), 0);
        char before0[1024];
        memset(before0, 0, sizeof(before0));
        //讀指令並且解密
        ssize_t readSomething1 = recv(peer_socket, before0, sizeof(before0), 0) ;
        char recvm[2048];
        memset(recvm, 0, sizeof(recvm));
        int bytesRead = RSA_private_decrypt(readSomething1, (const unsigned char *)before0,(unsigned char *)recvm, peerPrivateKeyRSA, RSA_PKCS1_PADDING);

        // char recvm[2048];
        // memset(recvm, 0, sizeof(recvm));
        // ssize_t bytesRead = recv(peer_socket, recvm, sizeof(recvm), 0);
        if (bytesRead == -1) {
            perror("Error receiving from peer");
            exit(EXIT_FAILURE);
        }
        printf("\nthe receiving data is :%s\n", recvm);
        if(!encryptAndSend(original_socket, recvm, serverPublicKey)){
            perror("fail to send it to the server\n");
        }
        close(peer_socket);
    }
    free(args);
    close(listen_socket);
    return NULL;
}


int main(int argc, char *argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
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
    char *clientPublicKey;
    char *clientPrivateKey;

    generateClientKeyPair(&clientPublicKey, &clientPrivateKey);
    BIO *privateKeyBio = BIO_new_mem_buf((void *)clientPrivateKey, -1);
    RSA *clientPrivateKeyRSA = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
    BIO_free(privateKeyBio);
    if(!clientPrivateKeyRSA){
        perror("Error reading RSA private key");
        exit(EXIT_FAILURE);
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
    char serverPublicKey[2048];
    memset(serverPublicKey, 0, sizeof(serverPublicKey));
    ssize_t bytesRead = recv(client_socket, serverPublicKey, sizeof(serverPublicKey) - 1, 0);
    send(client_socket, clientPublicKey, strlen(clientPublicKey) + 1, 0);
    while (1) {
        printf("Enter a command: ");
        char sendmsg[256];
        memset(sendmsg, 0, sizeof(sendmsg));
        fgets(sendmsg, sizeof(sendmsg), stdin);
        size_t len = strlen(sendmsg);
        if (len > 0 && sendmsg[len - 1] == '\n') sendmsg[len - 1] = '\0';
        bool isExit = false ;
        bool isTransaction = false;
        if (strcmp(sendmsg, "Exit") == 0) {//Exit
            if(!encryptAndSend(client_socket, sendmsg, serverPublicKey)){
                perror("fail to send message!");
                break;
            }
            isExit = true;
        }
        else if (strcmp(sendmsg, "List") == 0) {//List
            if(!encryptAndSend(client_socket, sendmsg, serverPublicKey)){
                perror("fail to send message!");
                break;
            }
        }
        else if (strstr(sendmsg, "REGISTER") != NULL && countCharOccurrences(sendmsg, '#') == 1) {//REGISTER
            if(!encryptAndSend(client_socket, sendmsg, serverPublicKey)){
                perror("fail to send message!");
                break;
            }
        }
        else if(countCharOccurrences(sendmsg, '#') == 1){//Login
            if(!encryptAndSend(client_socket, sendmsg, serverPublicKey)){
                perror("fail to send message!");
                break;
            }
            struct ThreadArgs args;
            char* tt = strtok(sendmsg, "#");
            tt = strtok(NULL, "#");
            args.port = atoi(tt);
            args.ip = server_ip;
            args.server_port = server_port;
            args.socketfd = client_socket;
            args.serverPublicKey = serverPublicKey;
            pthread_t listen_thread;
            if (pthread_create(&listen_thread, NULL, listen_handler, &args) != 0) {
                perror("Error creating listen_thread");
                return 1;
            } 
        }
        else if(countCharOccurrences(sendmsg, '#') == 2){ //A#100#B
            if(!encryptAndSend(client_socket, "List\n", serverPublicKey)){
                perror("fail to send message!");
                break;
            }
            char online_list[2048];
            memset(online_list, 0, sizeof(online_list));
            // 接收使用 clientPublicKey 加密過的 online_list
            ssize_t readList = recv(client_socket, online_list, sizeof(online_list), 0);
            if (readList == -1) {
                perror("Error receiving from server");
                exit(EXIT_FAILURE);
            }
            char decryptedList[2048];
            memset(decryptedList, 0, sizeof(decryptedList));
            // 使用 privateKey 解密
            BIO *privateKeyBio = BIO_new_mem_buf((void *)clientPrivateKey, -1);
            RSA *clientPrivateKeyRSA = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
            BIO_free(privateKeyBio);

            if (!clientPrivateKeyRSA) {
                perror("Error reading RSA private key");
                exit(EXIT_FAILURE);
            }

            int decryptedListBytes = RSA_private_decrypt(readList, (const unsigned char *)online_list, (unsigned char *)decryptedList, clientPrivateKeyRSA, RSA_PKCS1_PADDING);
            if (decryptedListBytes <= 0) {
                perror("Error decrypting online_list");
                exit(EXIT_FAILURE);
            }
            char temp[256];
            strcpy(temp, sendmsg);
            char sender[256];
            int amount;
            char receiver[256];
            sscanf(sendmsg, "%255[^#]#%d#%255s", sender, &amount, receiver);
            //printf("the sender is %s, amount is %d, receiver is %s\n", sender, amount, receiver);
            char *tok = strtok(decryptedList, "#\n");
            int amo = atoi(tok);
            if(amo >= amount){
                tok = strtok(NULL, "#\n");
                char *pk = tok;
                tok = strtok(NULL, "#n\n");//online count
                int cnt = atoi(tok);
                //printf("the balance is %d, the pk is %s, the online count is %d\n", amo, pk, cnt);
                for(int i = 0 ; i < cnt ; i++){
                    tok = strtok(NULL, "#\n");
                    char* username = tok;
                    tok = strtok(NULL, "#\n");
                    char* ip_address = tok;
                    tok = strtok(NULL, "#\n");
                    int portNum = atoi(tok);
                    if (strcmp(username, receiver) == 0) {
                        //printf("the target is %s, the ip is %s, port is %d\n", username, ip_address, portNum);
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
                            //printf("Fail to connect target client at IP: %s, Port: %d\n", inet_ntoa(targetAddress.sin_addr), ntohs(targetAddress.sin_port));
                            return 1;
                        }
                        else {
                            isTransaction = true;
                            //printf("Connecting to target client at IP: %s, Port: %d\n", inet_ntoa(targetAddress.sin_addr), ntohs(targetAddress.sin_port));
                            printf("the sending payment message is = %s\n", temp);
                            //傳送加密過後的訊息給 targetSocket
                            char peerPublicKey[2048];
                            memset(peerPublicKey, 0, sizeof(peerPublicKey));
                            ssize_t readSomething0 = recv(targetSocket, peerPublicKey, sizeof(peerPublicKey)-1, 0);
                            if(!encryptAndSend(targetSocket, temp, peerPublicKey)){
                                perror("Fail to send message to target client");
                                exit(EXIT_FAILURE);
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
        if(!isTransaction){
            char before[1024];
            memset(before, 0, sizeof(before));
            ssize_t readSomething = recv(client_socket, before, sizeof(before), 0);
            char response[2048];
            memset(response, 0, sizeof(response));
            int decryptedBytes = RSA_private_decrypt(readSomething, (const unsigned char *)before, (unsigned char *) response, clientPrivateKeyRSA, RSA_PKCS1_PADDING);
            if(decryptedBytes <= 0){
                perror("Error receiving from server1");
                break;
            }
            char *token = strtok(response, "\n");
            while (token != NULL) {
                printf("Received command: %s\n", token);
                token = strtok(NULL, "\n");
            }
        }
        if(isExit) break;
    }
    free(clientPrivateKey);
    free(clientPublicKey);
    close(client_socket);
    return 0;
}