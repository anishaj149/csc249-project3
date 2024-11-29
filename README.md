# Overview
This project simulates a secure server and client interacting through a VPN. The client and server will perform a handshake to exchange asymmetric and symmetric keys and then send a message to one another. 

# Format of certificate
Separates the ip, port, and key by dollar signs. 
$127.0.0.1$65432$(49993, 56533)

# Output

server output
Generated public key '(49993, 56533)' and private key '6540'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '$127.0.0.1$65432$(49993, 56533)'
Connection established, sending certificate '$127.0.0.1$65432$(49993, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(26785, 56533)[$127.0.0.1$65432$(49993, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 58335)
Server sent signed certificate to client. 
Symmetric key exchanged successfully.
Received client message: 'b'HMAC_6002298171171422174[symmetric_80018[Hello, world]]'' [55 bytes]
Decoded message 'Hello, world' from client
Responding 'Hello, world' to the client
Sending encoded response 'HMAC_6002298171171422174[symmetric_80018[Hello, world]]' back to the client
Symmetric key exchanged successfully.
server is done!

VPN output 
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 58334)
Received client message: 'b'127.0.0.1$65432'' [15 bytes]
Connecting to server at IP 127.0.0.1 and port 65432
Server connection established at IP 127.0.0.1 and port 65432
Sending message 'b'HMAC_6002298171171422174[symmetric_80018[Hello, world]]'' to server from client.
Message sent to server, waiting for reply.
Received server response: 'b'HMAC_6002298171171422174[symmetric_80018[Hello, world]]'' [55 bytes]
Forwarding server response to client
VPN is done!

client output
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (29748, 56533) from the certificate authority for verifying certificates
client starting - connecting to VPN at IP 127.0.0.1 and port 55554
establishing connection to server at 127.0.0.1 and port 127.0.0.1
client has received certificate from server through vpn.
Completed handshake.
connection established, sending message 'HMAC_6002298171171422174[symmetric_80018[Hello, world]]'
message sent, waiting for reply
Received raw response: 'HMAC_6002298171171422174[symmetric_80018[Hello, world]]' [55 bytes]
Decoded message Hello, world from server
client is done!

# Handshake walk through
The server will first send the signed certificate to the VPN which will forward it to the client. Then the client will verify the signed certificate using the certification authority to ensure that the server is who it says it is and receive the server's public key. After verification the client will generate a symmetric key and encrypt it with the server's public key so no one can read it in transit. Then the client will send the encrypted key to the VPN which will forward it to the server. The server will decrypt the symmetric key using its own private key.

# Limitations
One limitation is the encryption algorithms using the symmetric key. It doesn't change any of the message, it just concatenates a string with the symmetric key and message together. The actual message can be read through the encrypted message.

Another limitation is the HMAC verification algorithm. The function hashes on the message and the symmetric key. However because of the encryption scheme mentioned, we can pull the key and message directly from the cypher text. This means that anyone could easily generate the same hash, so the hmac does not actually authenticate. 

# Acknowledgements
I did not use any other person's help in this project. 
