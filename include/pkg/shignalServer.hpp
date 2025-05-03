#pragma once

#include <iostream>
#include <utility>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
// #include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

class ShignalServerClient {
public:
  ShignalServerClient(ShignalServerConfig shignalServerConfig);
  void run(int port);
  void HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);

  // TODO: add functions for handling incoming messages
  void HandleIncomingMessage(std::shared_ptr<NetworkDriver> network_driver);
  // pseudocode for handling incoming message:
  // 1. check if incoming is prekey or generic
  // 2. if prekey, do updates for prekey and return
  // 3. if generic, check if sender is in onlineUsers, if no, jump to step 5
  // 4. if sender is in onlineUsers, add message to user's inbox, return
  // 5. if sender is not in onlineUsers, add message to user's inbox, return

private:
  ShignalServerConfig shignalServerConfig;
  std::shared_ptr<CLIDriver> cli_driver;

  // map of online users for whom to directly forward messages
  std::map<std::string,shared_ptr<NetworkDriver>> onlineUsers;

  // map of users to their inboxes for storing messages while offline
  std::map<std::string,std::deque<Shignal_GenericMessage>> userInboxes;
  
  // map of epochID to a map of userID to PrekeyBundles
  std::map<std::string,std::map<std::string,PrekeyBundle>> epochPrekeys;

  void ListenForConnections(int port);
  void Reset(std::string _);
  void Users(std::string _);
};