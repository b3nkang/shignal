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
  ShignalServerClient();
  void run();
  void HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);

  void HandleShignalMessage(std::shared_ptr<NetworkDriver> network_driver);
  void ListenForMessages();
  void HandleGenericMessage(std::vector<unsigned char> data);
  void HandlePrekeyBundle(std::vector<unsigned char> data);
  void HandlePrekeyBundleRequest(std::vector<unsigned char> data);
  void ReadLoop(std::shared_ptr<NetworkDriver> driver); // <-- ADD THIS
  void HandleOnlineMessage(std::vector<unsigned char> data, std::shared_ptr<NetworkDriver> driver);

private:
  int port;
  // ShignalServerConfig shignalServerConfig;
  std::shared_ptr<CLIDriver> cli_driver;

  // map of online users for whom to directly forward messages
  std::map<std::string,std::shared_ptr<NetworkDriver>> onlineUsers;

  // map of users to their inboxes for storing messages while offline
  std::map<std::string,std::deque<std::vector<unsigned char>>> userInboxes;
  
  // map of epochID to a map of userID to PrekeyBundles
  std::map<std::string,std::map<std::string,PrekeyBundle>> epochPrekeys;

  void ListenForConnections(int port);
  void Reset(std::string _);
  void Users(std::string _);
};