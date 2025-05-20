# shignal (shitty signal)

<img width="759" alt="image" src="https://github.com/user-attachments/assets/e55c7261-1ea3-4cce-ae16-42f1a3f2ee80" />

## Overview 
Shignal is a feeble attempt in applied cryptography to emulate the security protocols of the group chat and messaging service Signal. This in-progress implementation features complete group structure hiding from the server and offline messaging, while maintaining authenticated key exchange between all group chat users through prekey bundling to prevent MitM attacks. In the future, the goal is to implement asynchronous, offline rekeying to facilitate the leaving of group chat members.

The project is written in C++ with CryptoPP and, beyond the immediate Shignal functionality, also features manual implementations of AES encryption, decryption, HMAC tagging, signatures and certificates, and login and registration processes that use salting, peppering, and seeding. Extensive networking and concurrency work has also been completed to wire up all parties within the codebase.

## Shignal Workflows and Assumptions
### Intuition
At a high level, in order to support offline messaging, a centralized server that stores user messages is inevitable (ours is the ShignalServer). However, in order to obscure group structure and other characteristics to the server, it will only store user-to-user messages, acting as a "forwarder" between one user to another. As a result, all group state information is sorted by users themselves locally, and users must individually encrypt and send each message to every group member. All our server sees is the sender and receiver—information we unfortunately cannot abstract away in any practical implementation—but that is it. All messages of any kind—regular messages, admin messages, and add member messages, for example—appear to the server as random garbage, and nothing else can be gleaned about the hierarchy of the group (excluding side channel attacks like fanout patterns, but which are remedied with batching, random traffic, and delays which we deem out of scope).

### User-to-Shignal Communication
As is consistent with Rösler, Mainka, and Schwenk (2018), we assume the underlying communication protocol between the user and the ShignalServer is secure, through something like TLS. Our focus is on the security and integrity of messages between the users themselves. 

<img width="759" alt="image" src="https://github.com/user-attachments/assets/e41faa57-6cd0-4f68-971d-3a84c904160a" />

### Adding a Member to the Group Chat
This involves DHKE between the users directly, before the invitee receives the group state information and uploading their prekey bundle, before then doing two-sided authenticated key exchange (2KE) with all other member prekey bundles. All other members then also need to be notified of this new member's addition so that they can update their local group states appropriately and then perform asynchronous 2KE with the new member's uploaded prekey bundle. At the end of this flow, now everyone has visibility of the new member's messages and the new member can receive messages from everyone.

<img width="1068" alt="image" src="https://github.com/user-attachments/assets/db2f03dd-5bb5-4f01-9b7a-915ea425ba54" />

### Sending a Message to the Group Chat
The flow to send a message is comparatively much simpler. The user simply encrypts and sends their message N times where N is the number of group chat members, each time encrypting and tagging with their keys derived from the asynchrnous 2KE with all others' bundles. As such, the server has no way to see the actual message content aside from forwarding the message to the appropriate users, after which the recipient users (who have also done this async 2KE and thus have the keys) can decrypt and verify the sent message.

<img width="1065" alt="image" src="https://github.com/user-attachments/assets/e3b30247-43df-4fb7-8cf4-c9ea45ac1cd3" />

### Leaving from the Group Chat

Easily the most complicated flow (and also unimplemented), but the general idea is that just because a user says they are leaving does not mean that they lose the ability to receive messages from the group. In fact, they can continue to so long as the keys in their `DHKeyMap` remain valid. Thus all remaining users must rotate keys and send a fresh prekey bundle to the server. However, then, there are concurrency issues: when does a remaining member know that another's' prekey bundle is fresh or stale? Thus we have an `epochId` which stores "versions" of prekey bundles. When a user leaves, the admin shifts to a new epoch, allowing separate storage of new, fresh prekey bundles so that rekeying can happen safely.

<img width="1068" alt="image" src="https://github.com/user-attachments/assets/8ee751b1-ef5e-449d-8558-94cc12412898" />

### Signup and Login Flows

<img width="1064" alt="image" src="https://github.com/user-attachments/assets/c06e52a2-20b9-4f6a-8fa8-d5debd7e23ab" />
<img width="1063" alt="image" src="https://github.com/user-attachments/assets/f610d600-494a-4a02-a697-116cb6a60b83" />

## Running Shignal

### Building the Project and Starting the Servers

Run `cmake ..` and `cd` into the `/build` directory with `cd build`.

Then start the shitty `shignal_server` first in a terminal with:

```
./shignal_server
```

Next, in another terminal, from the `/build` directory, start the authentication server for login/registration. You can pick any port to run this on, but we use port `1234` for the auth server in the command below:

```
./auth_server 1234 ../config/server-config.json
```

### Spinning up Group Chat Users

Now, we can start spinning up users. Again, in up to three additional terminals (more if you manually add more user configs), from the `/build` directory, launch each user with the following:

```
./auth_user ../config/userX-config.json
```

where `userX` is `user0`, `user1`, or `user2` (or more if more configs are added).

Once this is run, the user should register (if the first time launching this user in the terminal) or login otherwise, again assuming the `auth_server` is running on port `1234`:

```
login localhost 1234
```

or

```
register localhost 1234
```

The server throws an error and will prompt for the correct command in the case the wrong command is supplied. The auth server terminal, upon execution of these commands in the user terminals, will also provide a log confirming the user has registered/logged in successfully.

### Creating a Group as Admin and Inviting a User

To create a group chat and ideally test functionality, we will need 3 users spun up in different terminals. We now assume there are these users are logged in/registered.

To "create" a group, one user should invite the other users to the group. To do this, these other users must be listening on a port for an invitation request, which can be done with:

```
listen <port>
```

in the invitee user's terminal, and where the `<port>` can be your choice.

```
invite <user> <port>
```

where `<user>` is the invitee user's name (check config for username), and the `<port>` is the same as the invitee is already listening on.

Once the `invite` request is sent, the invitee user's terminal will then prompt with the following:

```
Accept invite? (y/n):
```

Once this reply is sent, a confirmation should print to both the admin and invitee terminals, indicating that the invitee has successfully joined.

Repeat this for any other users to add them to the group chat. All `invite`s must be sent by the original admin, not an added group member, or else they will not succeed.

### Sending messages to the group chat

Once user(s) are successfully added to the group chat, messages can be sent with the following format from any user in the group to the others:

```
send <message>
```

where `<message>` can be any string of any characters. Once the message is sent, it should appear in all other added group chat member terminals.

### Additional Functionality, TBD

- Offline messaging is currently broken, although messages are stored offline and the infrastructure is completed. This will be the next item to fix.
- Group chat leaving is not implemented in any extent so far. This is long-run feature to implement and will follow the diagram flows.

## Sample Run of Shignal

Here is a full sample run with commands and corresponding output for what to expect when testing Shignal.

| Auth Server                                                                       | Shignal Server                                                  | User2 (admin)                                                                    | User0 (tree)                                                                    | User1 (ben)                                                                    |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------- | :------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `./auth_server 1234 ../config/server-config.json`<br />Table created successfully |                                                                 |                                                                                  |                                                                                 |                                                                                |
|                                                                                   | `./shignal_server`<br />Signal server is listening on port 2700 |                                                                                  |                                                                                 |                                                                                |
|                                                                                   | Accepted new connection                                         | `./auth_user ../config/user2-config.json`                                        |                                                                                 |                                                                                |
|                                                                                   | Accepted new connection                                         |                                                                                  | `./auth_user ../config/user0-config.json`                                       |                                                                                |
|                                                                                   | Accepted new connection                                         |                                                                                  |                                                                                 | `./auth_user ../config/user1-config.json`                                      |
| Listening on port 1234<br />Connection handled successfully                       |                                                                 | `register localhost 1234` <br />Successfully registered/logged in as user: admin |                                                                                 |                                                                                |
| Listening on port 1234<br />Connection handled successfully                       |                                                                 |                                                                                  | `register localhost 1234` <br />Successfully registered/logged in as user: tree |                                                                                |
| Listening on port 1234<br />Connection handled successfully                       |                                                                 |                                                                                  |                                                                                 | `register localhost 1234` <br />Successfully registered/logged in as user: ben |
|                                                                                   |                                                                 |                                                                                  | `listen 2`<br />Listening for peer connections on port 2                        |                                                                                |
|                                                                                   |                                                                 | `invite tree 2` Invite message sent to tree                                      | You have been invited to join a group chat!<br />Accept invite? (y/n): y        |                                                                                |
|                                                                                   |                                                                 | tree accepted the invite; added to group chat!                                   | You have joined the group chat!                                                 |                                                                                |
|                                                                                   |                                                                 | `send hi tree`                                                                   | From admin:<br />hi tree                                                        |                                                                                |
|                                                                                   |                                                                 | From tree:<br />hi admin                                                         | `send hi admin`                                                                 |                                                                                |
|                                                                                   |                                                                 |                                                                                  |                                                                                 | `listen 71`                                                                    |
|                                                                                   |                                                                 | `invite ben 71` <br />Invite message sent to ben                                 |                                                                                 | You have been invited to join a group chat!<br />Accept invite? (y/n): y       |
|                                                                                   |                                                                 | ben accepted the invite; added to group chat!                                    | New user ben added to group chat.                                               | You have joined the group chat!                                                |
|                                                                                   |                                                                 |                                                                                  |                                                                                 | `send hi everyone!`                                                            |
|                                                                                   |                                                                 | From ben:<br /> hi everyone!                                                     | From ben:<br /> hi everyone!                                                    |                                                                                |

Note well:

1. lots of gibberish will be printed from the Shignal Server after it accepts the new connections, but for the purposes of the user, the logs are not relevant.
2. the command `register localhost 1234` should be replaced by `login localhost 1234` in all successive runs within a given terminal instance after the first.

## Persisting/Known Issues, and Possible Fixes

- **user_ids sent in the clear to the server**
    - server knows the sender and receiver of a message
    - observer can easily build a communication graph to figure out the group
    - fix: ephemeral rotating IDs with a lookup table (ran out of time/scope blew up)
- **messages to all other gc members sent at the same time**
    - server is able to deduce group structure through fanout patterns
    - could probably side channel groups over time
    - fix: batch messages and random delays
    - fix: dummy messages that do nothing
- **prekey bundle on server is still insecure**
    - prekey can be tampered with, ideally needs to be signed, replay attack weakness
    - fix: implement X3DH (out of scope)
- **epoch_id for facilitating rekeying without synchronization issues leaks info**
    - the server can tell when rekeying happens begins (and who might be involved)
    - we try to avoid this by having garbage epoch_ids also as noise
    - improved fix: abstract away Prekey_Message into generic Control_Message
    - fix: batching, delays, other tactics similar to the gc timing issue
- **no timestamps supported currently, to add**
- **very long term goal: add ratcheting, implement lightweight TLS, old epoch eviction**

