#pragma once

#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

class UserClient {
public:
  UserClient(std::shared_ptr<NetworkDriver> network_driver,
             std::shared_ptr<NetworkDriver> shignal_driver,
             std::shared_ptr<CryptoDriver> crypto_driver,
             UserConfig user_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleServerKeyExchange();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleUserKeyExchange();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleUserKeyExchangeForInvite(std::shared_ptr<NetworkDriver> driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleBundleKeyExchange(PrekeyBundle &bundle, std::string memberId);
  void HandleLoginOrRegister(std::string input);
  void DoLoginOrRegister(std::string input);
  void HandleUser(std::string input);
  void DoInviteMember(std::string input,std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys, std::shared_ptr<NetworkDriver> userDriver);
  void DoJoinGroup(std::pair<SecByteBlock, SecByteBlock> keys, std::shared_ptr<NetworkDriver> userDriver);
  void DoSendGroupMessage(std::string input);
  void HandleShignalMessage(std::vector<unsigned char> data);
  void HandleAddControlMessage(std::vector<unsigned char> decMsg);
  void HandleMessagePayload(std::vector<unsigned char> decMsg);
  void HandleListen(std::string input);
  void HandleInviteMember(std::string input);
  void HandleJoinGroup(std::string input);
  void HandleSendGroupMessage(std::string input);
  void HandleDummy(std::string input);

private:
  std::string id;
  // std::string name;
  Certificate_Message certificate;
  GroupState_Message groupState;

  UserConfig user_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<NetworkDriver> shignal_driver;
  std::shared_ptr<NetworkDriver> peer_listener_driver;

  CryptoPP::RSA::PrivateKey RSA_signing_key;
  CryptoPP::RSA::PublicKey RSA_verification_key;
  CryptoPP::RSA::PublicKey RSA_server_verification_key;
  CryptoPP::RSA::PublicKey RSA_remote_verification_key;
  CryptoPP::SecByteBlock DH_sk;
  CryptoPP::SecByteBlock DH_pk;
  CryptoPP::SecByteBlock prg_seed;

  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  ShignalReceiveThread();
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
};
