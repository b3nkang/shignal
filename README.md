# shignal (shitty signal)

## Overview 
Shignal is a feeble attempt in applied cryptography to emulate the security protocols of the group chat and messaging service Signal. This in-progress implementation features complete group structure hiding from the server and offline messaging, while maintaining authenticated key exchange between all group chat users through prekey bundling to prevent MitM attacks. In the future, the goal is to implement asynchronous, offline rekeying to facilitate the leaving of group chat members.

The project is written in C++ with CryptoPP and, beyond the immediate Shignal functionality, also features manual implementations of AES encryption, decryption, HMAC tagging, signatures and certificates, and login and registration processes that use salting, peppering, and seeding. Extensive networking and concurrency work has also been completed to wire up all parties within the codebase.

<img width="759" alt="image" src="https://github.com/user-attachments/assets/e55c7261-1ea3-4cce-ae16-42f1a3f2ee80" />

## Running the group chat

### Building the project and starting the servers

Run `cmake ..` and `cd` into the `/build` directory with `cd build`.

Then start the shitty `shignal_server` first in a terminal with:

```
./shignal_server
```

Next, in another terminal, from the `/build` directory, start the authentication server for login/registration. You can pick any port to run this on, but we use port `1234` for the auth server in the command below:

```
./auth_server 1234 ../config/server-config.json
```

### Starting up group chat users

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

### Creating a group as admin and inviting a new member

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

### Additional functionality, TBD

- Offline messaging is currently broken, although messages are stored offline and the infrastructure is completed. This will be the next item to fix.
- Group chat leaving is not implemented in any extent so far. This is long-run feature to implement and will follow the diagram flows.

## Sample run of group chat

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
