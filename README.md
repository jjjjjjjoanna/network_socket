# network_socket
method: using socket program to build a secure person2person (P2P) micropayment system

A secure internet third-party payment system for user-to-user micropayments, with encrypted transmission capabilities. This system comprises three main functions:

1. Centralized management by the third-party payment server of client-side (user) operations, including account management, friend list management, authentication, and client account management.
2. Real-time communication between clients.
3. Encrypted communication between clients and servers, as well as between clients, with encryption keys (secret keys) agreed upon by the communicating parties.

The objective of this assignment is to design and implement a simple peer-to-peer transfer function among friends. Students will design and implement secure transmission software for a simple "secure third-party payment system for user-to-user micropayments," including both client and multithreaded server software, as well as secure transmission software writing.

The two main functionalities of the client side are:

- Secure communication with the third-party payment server.
- Secure one-on-one communication between clients.

The primary functionalities of the multi-threaded server side are:

- Accepting secure connections from clients and responding to requests with messages.

The main features of secure communication are:

- Encryption of communication between each client and server, as well as between clients, with encryption keys (secret keys) agreed upon by the communicating parties.

The communication messages between the Client and the Server primarily consist of four types:

Registration from the Client to the Server:

Message from the Client to the Server:
```
REGISTER#<UserAccountName>
```
Server response to the Client for successful or unsuccessful registration:
```
Successful: 100<space>OK<CRLF>
Unsuccessful: 210<space>FAIL<CRLF>
```
Login from the Client to the Server:
Message from the Client to the Server:
```
<UserAccountName>#<portNum>
```
If the user is registered, the Server responds with an online list in the following format:
```
<accountBalance><CRLF>
<serverPublicKey><CRLF>
<number of accounts online><CRLF>
<userAccount1>#<userAccount1_IPaddr>#<userAccount1_portNum><CRLF>
<userAccount2>#<userAccount2_ IPaddr>#<userAccount2_portNum><CRLF>
```
If the user is not registered, the Server responds with an authentication failure message:
```
220<space>AUTH_FAIL<CRLF>
```
Request for the latest account balance and online list from the Client to the Server:

Message from the Client to the Server:
```
List
```
Server response to the Client with the online list:
```
<accountBalance><CRLF>
<serverPublicKey><CRLF>
<number of accounts online><CRLF>
<userAccount1>#<userAccount1_IPaddr>#<userAccount1_portNum><CRLF>
<userAccount2>#<userAccount2_ IPaddr>#<userAccount2_portNum><CRLF>
```
Client program termination:

Message from the Client to the Server:
```
Exit
```
Server response to the Client:
```
Bye<CRLF>
```
Micropayment transaction message from the Client to the Server:

Message format between Clients:
```
<MyUserAccountName>#<payAmount>#<PayeeUserAccountName>
```
This message from Client A is encrypted using the public key of friend B. Upon receiving it, friend B decrypts it using their private key to obtain the transfer amount. After confirming the amount, friend B encrypts the message using the Server's public key and sends it to the Server (assuming B will not tamper with the amount). The Server decrypts it using its private key and updates the account balances of both parties. The message content is assumed to be ASCII text.
Note: The Server does not relay any messages for the Client.
