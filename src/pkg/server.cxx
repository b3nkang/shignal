#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config) {
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try {
    LoadRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_signing_key = keys.first;
    this->RSA_verification_key = keys.second;
    SaveRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _) {
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _) {
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0) {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames) {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function
 * should: 1) Handle key exchange with the user.
 * 2) Reads a UserToServer_IDPrompt_Message and determines whether the user is
 * attempting to login or register and calls the corresponding function.
 * 3) Disconnect the network_driver, then return true.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  try {
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleKeyExchange(network_driver,crypto_driver);
    std::vector<unsigned char> idPromptData = network_driver->read();
    std::vector<unsigned char>  decIdPromptData;
    bool valid;
    UserToServer_IDPrompt_Message idPromptMsg;
    std::tie(decIdPromptData,valid) = crypto_driver->decrypt_and_verify(keys.first,keys.second,idPromptData);
    if (!valid) {
      throw std::runtime_error("handleConnection: bad vrfy on idpromptmsg");
    }
    idPromptMsg.deserialize(decIdPromptData);
    if (idPromptMsg.new_user) {
      HandleRegister(network_driver,crypto_driver,idPromptMsg.id,keys);
    } else {
      HandleLogin(network_driver,crypto_driver,idPromptMsg.id,keys);
    }
    network_driver->disconnect();
    return true;
  } catch (...) {
    this->cli_driver->print_warning("Connection threw an error");
    network_driver->disconnect();
    return false;
  }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 2) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  std::vector<unsigned char> userMsgData = network_driver->read();
  UserToServer_DHPublicValue_Message userMsg;
  userMsg.deserialize(userMsgData);

  DH DH_obj;
  SecByteBlock DHsk;
  SecByteBlock DHpk;
  std::tie(DH_obj,DHsk,DHpk) = crypto_driver->DH_initialize();

  std::vector<unsigned char> toSign = concat_byteblocks(DHpk,userMsg.public_value);
  std::string sig = crypto_driver->RSA_sign(this->RSA_signing_key,toSign);

  ServerToUser_DHPublicValue_Message sendingMsg;
  sendingMsg.server_public_value = DHpk;
  sendingMsg.user_public_value = userMsg.public_value;
  sendingMsg.server_signature = sig;

  std::vector<unsigned char> serverMsgData;
  sendingMsg.serialize(serverMsgData);
  network_driver->send(serverMsgData);

  SecByteBlock DHshared(DH_obj.AgreedValueLength());
  DHshared = crypto_driver->DH_generate_shared_key(DH_obj,DHsk,userMsg.public_value);
  SecByteBlock AESkey(AES::DEFAULT_KEYLENGTH);
  AESkey = crypto_driver->AES_generate_key(DHshared);
  SecByteBlock HMACkey(SHA256::BLOCKSIZE);
  HMACkey = crypto_driver->HMAC_generate_key(DHshared);

  return {AESkey,HMACkey};
}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  UserRow user = db_driver->find_user(id);
  if (user.user_id.empty()) {
      throw std::runtime_error("server login: user no in db");
  }

  ServerToUser_Salt_Message saltMsg;
  saltMsg.salt = user.password_salt;
  std::vector<unsigned char> saltData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&saltMsg);
  network_driver->send(saltData);

  UserToServer_HashedAndSaltedPassword_Message hpwdMsg;
  std::vector<unsigned char> hpwdData = network_driver->read();
  std::vector<unsigned char> decHpwdData;
  bool valid;
  std::tie(decHpwdData,valid) = crypto_driver->decrypt_and_verify(keys.first,keys.second,hpwdData);
  if (!valid) {
      throw std::runtime_error("server login: bad hpwd vrfy");
  }
  hpwdMsg.deserialize(decHpwdData);

  bool pwdFound = false;
  for (int p = 0; p < 256; p++) {
    std::string pepper(1,static_cast<unsigned char>(p));
    std::string concatedPepper = hpwdMsg.hspw + pepper;
    if (user.password_hash == crypto_driver->hash(concatedPepper)) {
      pwdFound = true;
      break;
    }

  }
  if (!pwdFound) {
      throw std::runtime_error("server login: no pwd found after adding pepper");
  }

  UserToServer_PRGValue_Message prgMsg;
  std::vector<unsigned char> prgData = network_driver->read();
  std::vector<unsigned char> decPrgData;
  bool valid2;
  std::tie(decPrgData,valid2) = crypto_driver->decrypt_and_verify(keys.first,keys.second,prgData);
  if (!valid2) {
      throw std::runtime_error("server login: bad prgMsg vrfy");
  }
  prgMsg.deserialize(decPrgData);

  Integer rn = crypto_driver->nowish();
  bool valid3 = false;
  for (int i = 0; i < 60; i++) {
    SecByteBlock expected = crypto_driver->prg(string_to_byteblock(user.prg_seed),integer_to_byteblock(rn-Integer(i)),PRG_SIZE);
    if (byteblock_to_string(prgMsg.value)==byteblock_to_string(expected)) {
        valid3 = true;
        break;
    }
  }
  if (!valid3) {
      throw std::runtime_error("server login: bad 2fa");
  }

  UserToServer_VerificationKey_Message vkMsg;
  std::vector<unsigned char> vkData = network_driver->read();
  std::vector<unsigned char> decVkData;
  bool valid4;
  std::tie(decVkData,valid4) = crypto_driver->decrypt_and_verify(keys.first,keys.second,vkData);
  if (!valid4) {
      throw std::runtime_error("server login: bad vk vrfy");
  }
  vkMsg.deserialize(decVkData);

  std::vector<unsigned char> toSign = concat_string_and_rsakey(id,vkMsg.verification_key);
  std::string signature = crypto_driver->RSA_sign(this->RSA_signing_key,toSign);

  Certificate_Message certificate;
  certificate.verification_key = vkMsg.verification_key;
  certificate.id = id;
  certificate.server_signature = signature;

  ServerToUser_IssuedCertificate_Message certificateMsg;
  certificateMsg.certificate = certificate;
  std::vector<unsigned char> certificateData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&certificateMsg);
  network_driver->send(certificateData);
}

/**
 * Register the given user. This function should:
 * 1) Confirm that the user in not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * 6) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  UserRow lookForUser = db_driver->find_user(id);
  if (!lookForUser.user_id.empty()) {
      throw std::runtime_error("server reg: user already in db");
  }

  UserRow user;
  user.user_id = id;

  std::string salt = byteblock_to_string(crypto_driver->png(SALT_SIZE));

  ServerToUser_Salt_Message saltMsg;
  saltMsg.salt = salt;
  std::vector<unsigned char> saltData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&saltMsg);
  network_driver->send(saltData);
  user.password_salt = salt;

  UserToServer_HashedAndSaltedPassword_Message hpwdMsg;
  std::vector<unsigned char> hpwdData = network_driver->read();
  std::vector<unsigned char> decHpwdData;
  bool valid;
  std::tie(decHpwdData,valid) = crypto_driver->decrypt_and_verify(keys.first,keys.second,hpwdData);
  if (!valid) {
      throw std::runtime_error("server reg: bad hpwdMsg vrfy");
  }
  hpwdMsg.deserialize(decHpwdData);
  std::string concatedPepper = hpwdMsg.hspw + byteblock_to_string(crypto_driver->png(PEPPER_SIZE));
  std::string hashed = crypto_driver->hash(concatedPepper);
  user.password_hash = hashed;

  SecByteBlock seed = crypto_driver->png(PRG_SIZE);
  ServerToUser_PRGSeed_Message seedMsg;
  seedMsg.seed = seed;
  std::vector<unsigned char> seedData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&seedMsg);
  network_driver->send(seedData);
  user.prg_seed = byteblock_to_string(seed);

  UserToServer_PRGValue_Message prgMsg;
  std::vector<unsigned char> prgData = network_driver->read();
  std::vector<unsigned char> decPrgData;
  bool valid2;
  std::tie(decPrgData,valid2) = crypto_driver->decrypt_and_verify(keys.first,keys.second,prgData);
  if (!valid2) {
      throw std::runtime_error("server reg: bad prgMsg vrfy");
  }
  prgMsg.deserialize(decPrgData);

  Integer rn = crypto_driver->nowish();
  bool valid3 = false;
  for (int i = 0; i < 60; i++) {
    SecByteBlock expected = crypto_driver->prg(seed,integer_to_byteblock(rn-Integer(i)),PRG_SIZE);
    if (byteblock_to_string(prgMsg.value)==byteblock_to_string(expected)) {
        valid3 = true;
        break;
    }
  }
  if (!valid3) {
      throw std::runtime_error("server reg: bad 2fa");
  }

  UserToServer_VerificationKey_Message vkMsg;
  std::vector<unsigned char> vkData = network_driver->read();
  std::vector<unsigned char> decVkData;
  bool valid4;
  std::tie(decVkData,valid4) = crypto_driver->decrypt_and_verify(keys.first,keys.second,vkData);
  if (!valid4) {
      throw std::runtime_error("server reg: bad vk vrfy");
  }
  vkMsg.deserialize(decVkData);

  std::vector<unsigned char> toSign = concat_string_and_rsakey(id,vkMsg.verification_key);
  std::string signature = crypto_driver->RSA_sign(this->RSA_signing_key,toSign);

  Certificate_Message certificate;
  certificate.verification_key = vkMsg.verification_key;
  certificate.id = id;
  certificate.server_signature = signature;

  ServerToUser_IssuedCertificate_Message certificateMsg;
  certificateMsg.certificate = certificate;
  std::vector<unsigned char> certificateData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&certificateMsg);
  network_driver->send(certificateData);

  db_driver->insert_user(user);
}
