#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/shignalServer.hpp"
#include "../../include/pkg/user.hpp"


/**
 * Constructor
 */
ShignalServerClient::ShignalServerClient() {
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();
  this->port = 2700; // fixed port, in tribute to 2700chess.com
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ShignalServerClient::run() {
  std::thread listener_thread(&ShignalServerClient::ListenForMessages, this);
  listener_thread.detach();

  REPLDriver<ShignalServerClient> repl = REPLDriver<ShignalServerClient>(this);
  // repl.add_action("online", "show online users", &SignalServerClient::ShowOnlineUsers);
  repl.run();
}

// void ShignalServerClient::ListenForMessages() {
//   while (true) {
//     std::shared_ptr<NetworkDriver> driver = std::make_shared<NetworkDriverImpl>();
//     driver->listen(this->port);
//     std::thread(&ShignalServerClient::HandleShignalMessage, this, driver).detach();
//   }
// }

void ShignalServerClient::ListenForMessages() {
  std::shared_ptr<NetworkDriverImpl> listener = std::make_shared<NetworkDriverImpl>();
  listener->prepare_listener(this->port);
  this->cli_driver->print_success("Signal server is listening on port " + std::to_string(this->port));

  while (true) {
    std::shared_ptr<NetworkDriver> driver = listener->accept();
    this->cli_driver->print_info("Accepted new connection");
    std::thread(&ShignalServerClient::ReadLoop, this, driver).detach();
  }
}

void ShignalServerClient::ReadLoop(std::shared_ptr<NetworkDriver> driver) {
  while (true) {
    std::vector<unsigned char> data;
    try {
      data = driver->read();
    } catch (const std::runtime_error &e) {
      this->cli_driver->print_warning("Client disconnected or read failed.");
      return;
    }
    unsigned char msgType = data[0];
    switch (msgType) {
      case MessageType::Shignal_GenericMessage:
        this->cli_driver->print_info("Shignal received Shignal_GenericMessage, handling...");
        HandleGenericMessage(data);
        break;
      case MessageType::UserToShignal_PrekeyMessage:
        this->cli_driver->print_info("Shignal received UserToShignal_PrekeyMessage, handling...");
        HandlePrekeyBundle(data);
        break;
      case MessageType::UserToShignal_OnlineMessage:
        this->cli_driver->print_info("Shignal received UserToShignal_OnlineMessage, handling...");
        HandleOnlineMessage(data, driver);
        break;
      case MessageType::UserToShignal_RequestPrekeyBundle:
        this->cli_driver->print_info("Shignal received UserToShignal_RequestPrekeyBundle, handling...");
        HandlePrekeyBundleRequest(data);
        break;
      default:
        this->cli_driver->print_warning("Unknown message type received.");
        break;
    }
  }
}


// void ShignalServerClient::HandleShignalMessage(std::shared_ptr<NetworkDriver> driver) {
//   std::vector<unsigned char> data = driver->read();
//   unsigned char msgType = data[0]; 

//   switch (msgType) {
//     case MessageType::Shignal_GenericMessage:
//       this->cli_driver->print_info("Shignal received Shignal_GenericMessage, handling...");
//       HandleGenericMessage(data);
//       break;
//     case MessageType::UserToShignal_PrekeyMessage:
//       this->cli_driver->print_info("Shignal received UserToShignal_PrekeyMessage, handling...");
//       HandlePrekeyBundle(data);
//       break;
//     case MessageType::UserToShignal_OnlineMessage:
//       this->cli_driver->print_info("Shignal received UserToShignal_OnlineMessage, handling...");
//       HandleOnlineMessage(data,driver);
//       break;
//     case MessageType::UserToShignal_RequestPrekeyBundle:
//       this->cli_driver->print_info("Shignal received UserToShignal_RequestPrekeyBundle, handling...");
//       HandlePrekeyBundleRequest(data);
//       break;
//     default:
//       this->cli_driver->print_warning("Unknown message type received.");
//       break;
//   }

//   // driver->disconnect();
// }

void ShignalServerClient::HandleGenericMessage(std::vector<unsigned char> data) {
  Shignal_GenericMessage msg;
  msg.deserialize(data);
  this->cli_driver->print_info("Handling Generic Message...");

  // if recipient is "online" according to the map, optimistically send
  if (this->onlineUsers.contains(msg.recipientId)) {
    std::shared_ptr<NetworkDriver> &driver = this->onlineUsers.at(msg.recipientId);
    try {
      driver->send(data);
      this->cli_driver->print_info("Message sent to online user: " + msg.recipientId);
    } catch (const std::runtime_error &e) {
      this->cli_driver->print_warning("Send failed; marking " + msg.recipientId + " as offline.");
      // mark now as offline
      this->onlineUsers.erase(msg.recipientId);
      // add to inbox
      this->userInboxes[msg.recipientId].push_back(msg);
    }
  } else {
    this->cli_driver->print_info("Recipient offline; message stored.");
    this->userInboxes[msg.recipientId].push_back(msg);
  }
  this->cli_driver->print_info("Message forwarding execution finished.");
}

void ShignalServerClient::HandleOnlineMessage(std::vector<unsigned char> data,std::shared_ptr<NetworkDriver> driver) {
  UserToShignal_OnlineMessage msg;
  msg.deserialize(data);
  this->cli_driver->print_info("Handling Online Status in Shignal...");

  // add to online users map now
  // driver->listen(this->port);
  this->onlineUsers[msg.userId] = driver;

  // check if the user has any messages in their inbox
  // if so, send them
  if (this->userInboxes.contains(msg.userId)) {
    auto &inbox = this->userInboxes.at(msg.userId);
    while (!inbox.empty()) {
      Shignal_GenericMessage &message = inbox.front();
      this->cli_driver->print_info("Sending offline message from inbox to " + msg.userId);
      driver->send(message.ciphertext);
      inbox.pop_front();
    }
    this->userInboxes.erase(msg.userId);
  }
  this->cli_driver->print_info("Online status handling execution finished.");
}

/**
 * Stores a prekey bundle in the epochPrekeys map.
 */
void ShignalServerClient::HandlePrekeyBundle(std::vector<unsigned char> data) {
  UserToShignal_PrekeyMessage msg;
  msg.deserialize(data);
  this->cli_driver->print_info("Handling PrekeyBundle from: " + msg.userId);

  // if new epoch and no bucket yet, make it
  if (!this->epochPrekeys.contains(msg.epochId)) {
    this->epochPrekeys[msg.epochId] = std::map<std::string, PrekeyBundle>();
  }

  // store bundle
  this->epochPrekeys[msg.epochId][msg.userId] = msg.prekeyBundle;
  this->cli_driver->print_success("Stored PrekeyBundle for user " + msg.userId + " in epoch " + msg.epochId);

  // vrfy inbox exists for this user, if not, create it since it is a new user sending us their prekey bundle
  if (!this->userInboxes.contains(msg.userId)) {
    this->cli_driver->print_success("Creating inbox for new user: " + msg.userId);
    this->userInboxes[msg.userId] = std::deque<Shignal_GenericMessage>();
  }
}

/**
 * Looks up a prekey bundle in the epochPrekeys map and sends it to the user.
 * ASSUMES A USER WILL NOT GO OFFLINE BETWEEN REQUESTING AND RECEIVING A PREKEY BUNDLE.
 */
void ShignalServerClient::HandlePrekeyBundleRequest(std::vector<unsigned char> data) {
  UserToShignal_RequestPrekeyBundle msg;
  msg.deserialize(data);
  this->cli_driver->print_info("Handling PrekeyBundleRequest from: " + msg.requestorId);

  // check if we have the prekey bundle
  if (this->epochPrekeys.contains(msg.epochId) && this->epochPrekeys[msg.epochId].contains(msg.requestedId)) {
    // send the prekey bundle
    ShignalToUser_PrekeyBundleResponse response;
    response.found = true;
    response.prekeyBundle = this->epochPrekeys[msg.epochId][msg.requestedId];
    std::vector<unsigned char> responseData;
    response.serialize(responseData);
    this->cli_driver->print_info("Found PrekeyBundle for " + msg.requestedId + ", sending to " + msg.requestorId);
    this->cli_driver->print_info("Verifying that user is online... ");
    if (this->onlineUsers.contains(msg.requestorId)) {
      this->cli_driver->print_info("Requestor "+msg.requestorId+" is online.");
      this->onlineUsers[msg.requestorId]->send(responseData);
      this->onlineUsers[msg.requestorId]->send(responseData);
      this->onlineUsers[msg.requestorId]->send(responseData);

      this->cli_driver->print_success("Sent PrekeyBundle to " + msg.requestorId);

    } else {
      this->cli_driver->print_warning("Requestor "+msg.requestorId+" is offline. Aborting.");
      return;
      // this->cli_driver->print_warning("Sending PrekeyBundle to offline user, they will receive it when they come online.");
      // // add to inbox
      // this->userInboxes[msg.requestorId].push_back(response);
      // this->cli_driver->print_info("Added PrekeyBundle to inbox for " + msg.requestorId);
    }
    // this->cli_driver->print_info("Is useronline... "+onlineUsers.contains(msg.requestorId));
    // this->onlineUsers[msg.requestorId]->send(responseData);
    // this->cli_driver->print_success("Sent PrekeyBundle to " + msg.requestorId);
  } else {
    // send not found message
    ShignalToUser_PrekeyBundleResponse response;
    response.found = false;
    std::vector<unsigned char> responseData;
    response.serialize(responseData);
    this->onlineUsers[msg.requestorId]->send(responseData);
    this->cli_driver->print_warning("Sent reponse, PrekeyBundle not found for " + msg.requestedId);
  }
}