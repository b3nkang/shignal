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
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<NetworkDriver> shignal_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->shignal_driver = shignal_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadRSAPublicKey(user_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->RSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run() {
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister); // TODO: handle this case where we need to empty the inbox for an offline user
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server. This function should:
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature.
 * 3) Verify that the public value the server received is g^a.
 * 4) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {
  DH DH_obj;
  SecByteBlock DHsk;
  SecByteBlock DHpk;
  std::tie(DH_obj,DHsk,DHpk) = this->crypto_driver->DH_initialize();

  UserToServer_DHPublicValue_Message sendingMsg;
  sendingMsg.public_value = DHpk;
  std::vector<unsigned char> sendingMsgData;
  sendingMsg.serialize(sendingMsgData);
  this->network_driver->send(sendingMsgData);

  std::vector<unsigned char> serverAnsData = this->network_driver->read();
  ServerToUser_DHPublicValue_Message serverMsg;
  serverMsg.deserialize(serverAnsData);

  std::vector<unsigned char> signedData = concat_byteblocks(serverMsg.server_public_value,serverMsg.user_public_value);
  bool isVerified = this->crypto_driver->RSA_verify(this->RSA_server_verification_key,signedData,serverMsg.server_signature);
  if (!isVerified) {
    throw std::runtime_error("bad server sig");
  }
  if (byteblock_to_string(serverMsg.user_public_value) != byteblock_to_string(DHpk)) {
    throw std::runtime_error("bad public val");
  }
  SecByteBlock DHshared(DH_obj.AgreedValueLength());
  DHshared = crypto_driver->DH_generate_shared_key(DH_obj,DHsk,serverMsg.server_public_value);
  SecByteBlock AESkey(AES::DEFAULT_KEYLENGTH);
  AESkey = crypto_driver->AES_generate_key(DHshared);
  SecByteBlock HMACkey(SHA256::BLOCKSIZE);
  HMACkey = crypto_driver->HMAC_generate_key(DHshared);
  return {AESkey, HMACkey};
}

/**
 * Diffie-Hellman key exchange with another user. This function shuold:
 * 1) Generate a keypair, a, g^a, signs it, and sends it to the other user.
 *    Use concat_byteblock_and_cert to sign the message.
 * 2) Receive a public value from the other user and verifies its signature and
 * certificate.
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's verification key in RSA_remote_verification_key.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {
  DH DH_obj;
  SecByteBlock DHsk;
  SecByteBlock DHpk;
  std::tie(DH_obj,DHsk,DHpk) = this->crypto_driver->DH_initialize();

  std::vector<unsigned char> toSign = concat_byteblock_and_cert(DHpk,this->certificate);
  std::string sig = crypto_driver->RSA_sign(this->RSA_signing_key,toSign);

  UserToUser_DHPublicValue_Message sendingMsg;
  sendingMsg.public_value = DHpk;
  sendingMsg.certificate = this->certificate;
  sendingMsg.user_signature = sig;
  std::vector<unsigned char> sendingMsgData;
  sendingMsg.serialize(sendingMsgData);
  this->network_driver->send(sendingMsgData);

  std::vector<unsigned char> incomingData = network_driver->read();
  UserToUser_DHPublicValue_Message incomingMsg;
  incomingMsg.deserialize(incomingData);

  std::vector<unsigned char> certificateData = concat_string_and_rsakey(incomingMsg.certificate.id,incomingMsg.certificate.verification_key);
  bool isVerifiedCert = this->crypto_driver->RSA_verify(this->RSA_server_verification_key,certificateData,incomingMsg.certificate.server_signature);
  if (!isVerifiedCert) {
    throw std::runtime_error("bad incoming cert");
  }
  std::vector<unsigned char> userData = concat_byteblock_and_cert(incomingMsg.public_value,incomingMsg.certificate);
  bool isVerifiedUser = this->crypto_driver->RSA_verify(incomingMsg.certificate.verification_key,userData,incomingMsg.user_signature);
  if (!isVerifiedUser) {
    throw std::runtime_error("bad incoming user sig");
  }

  this->RSA_remote_verification_key = incomingMsg.certificate.verification_key;
  SecByteBlock DHshared(DH_obj.AgreedValueLength());
  DHshared = crypto_driver->DH_generate_shared_key(DH_obj,DHsk,incomingMsg.public_value);
  SecByteBlock AESkey(AES::DEFAULT_KEYLENGTH);
  AESkey = crypto_driver->AES_generate_key(DHshared);
  SecByteBlock HMACkey(SHA256::BLOCKSIZE);
  HMACkey = crypto_driver->HMAC_generate_key(DHshared);
  return {AESkey, HMACkey};
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
}

/**
 * User login or register. This function should:
 * 1) Handles key exchange with the server.
 * 2) Tells the server our ID and intent.
 * 3) Receives a salt from the server.
 * 4) Generates and sends a hashed and salted password.
 * 5) (if registering) Receives a PRG seed from the server, store in
 * this->prg_seed.
 * 6) Generates and sends a 2FA response.
 * 7) Generates a RSA keypair, and send vk to the server for signing.
 * 8) Receives and save cert in this->certificate.
 * 9) Receives and saves the keys, certificate, and prg seed.
 * Remember to store RSA keys in this->RSA_signing_key and
 * this->RSA_verification_key
 */
void UserClient::DoLoginOrRegister(std::string input) {
  // TODO: implement me!
  bool isRegistering = (input == "register");
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleServerKeyExchange();
  UserToServer_IDPrompt_Message idPromptMsg;
  idPromptMsg.id = this->user_config.user_username;
  if (isRegistering) {
    idPromptMsg.new_user = true;
  } else {
    idPromptMsg.new_user = false;
  }
  std::vector<unsigned char> idPromptData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&idPromptMsg);
  network_driver->send(idPromptData);

  std::vector<unsigned char> saltData = network_driver->read();
  ServerToUser_Salt_Message saltMsg;
  std::vector<unsigned char> decSaltData;
  bool valid;
  std::tie(decSaltData,valid) = crypto_driver->decrypt_and_verify(keys.first,keys.second,saltData);
  if (!valid) {
    throw std::runtime_error("user: bad salt vrfy");
  }
  saltMsg.deserialize(decSaltData);
  
  UserToServer_HashedAndSaltedPassword_Message hpwdMsg;
  std::string hpwd = this->crypto_driver->hash(this->user_config.user_password + saltMsg.salt);
  hpwdMsg.hspw = hpwd;
  std::vector<unsigned char> hpwdData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&hpwdMsg);
  network_driver->send(hpwdData);

  if (isRegistering) {
    std::vector<unsigned char> seedData = network_driver->read();
    ServerToUser_PRGSeed_Message seedMsg;
    std::vector<unsigned char> decSeedData;
    bool valid2;
    std::tie(decSeedData,valid2) = crypto_driver->decrypt_and_verify(keys.first,keys.second,seedData);
    if (!valid2) {
      throw std::runtime_error("user: bad prg seed vrfy");
    }
    seedMsg.deserialize(decSeedData);
    this->prg_seed = seedMsg.seed;
  }

  UserToServer_PRGValue_Message prgValueMsg;
  Integer rn = this->crypto_driver->nowish();
  prgValueMsg.value = this->crypto_driver->prg(this->prg_seed,integer_to_byteblock(rn),PRG_SIZE);
  std::vector<unsigned char> prgValueData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&prgValueMsg);
  network_driver->send(prgValueData);

  UserToServer_VerificationKey_Message vkMsg;
  RSA::PrivateKey sk;
  RSA::PublicKey pk;
  std::tie(sk,pk) = this->crypto_driver->RSA_generate_keys();
  vkMsg.verification_key = pk;
  std::vector<unsigned char> vkData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&vkMsg);
  network_driver->send(vkData);

  ServerToUser_IssuedCertificate_Message certificateMsg;
  std::vector<unsigned char> certificateData = network_driver->read();
  std::vector<unsigned char> decCertificateData;
  bool valid3;
  std::tie(decCertificateData,valid3) = crypto_driver->decrypt_and_verify(keys.first,keys.second,certificateData);
  if (!valid3) {
      throw std::runtime_error("user: bad certificate verification");
  }
  certificateMsg.deserialize(decCertificateData);
  this->certificate = certificateMsg.certificate;
  SaveCertificate(this->user_config.user_certificate_path,this->certificate);

  this->RSA_signing_key = sk;
  this->RSA_verification_key = pk;
  SaveRSAPrivateKey(this->user_config.user_signing_key_path,this->RSA_signing_key);
  SaveRSAPublicKey(this->user_config.user_verification_key_path,this->RSA_verification_key);
  SavePRGSeed(this->user_config.user_prg_seed_path,this->prg_seed);
  this->id = this->user_config.user_username;
  this->cli_driver->print_success("Successfully registered/logged in as " + this->id);
  

}


// =================================================================
// FUNCTIONS FOR ADD MEMBER DIAGRAM WORKFLOW START BELOW
// =================================================================

/**
 * Assumes authenticated KE with given recipientId has already been done.
 * 
 * Sends invite message to a group chat to a recipient. If GroupState_Message of this user (the sender) is uninitialized,
 * then this user (sender) will create the group chat and become the admin of the group.
 * 
 * Then waits for a reply from the recipient. If the recipient accepts, then the admin sends group info to the member and
 * initiates a broadcast AdminToUser_Add_ControlMessage to all other members of the group.
 */
void UserClient::DoInviteMember(std::string recipientId, std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  // check if groupstate is uninitialized
  if (this->groupState.adminId.empty()) {
    // init basic fields
    std::string groupId = byteblock_to_string(crypto_driver->png(16));
    std::string epochId = byteblock_to_string(crypto_driver->png(16));
    this->groupState.groupId = groupId;
    this->groupState.epochId = epochId;
    this->groupState.members.insert(this->id);
    // init admin fields
    this->groupState.adminId = this->id;
    this->groupState.adminVerificationKey = this->RSA_verification_key;
    this->groupState.adminCertificate = this->certificate;
  } else {
    // check if this user is the admin
    if (this->groupState.adminId == this->id) {
      this->cli_driver->print_success("You are attempting to send an invite to: "+recipientId);
    } else {
      this->cli_driver->print_warning("You are not the admin of this group chat. You do not have permission to send invites.");
      return;
    }
  }
  // check if recipientId is in the group
  if (this->groupState.members.find(recipientId) != this->groupState.members.end()) {
    this->cli_driver->print_warning("Recipient is already in the group chat.");
    return;
  }
  // send the invite message
  AdminToUser_InviteMessage inviteMsg;
  inviteMsg.inviteMsg = "You have been invited to join a group chat! Do you accept?";
  std::vector<unsigned char> inviteData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&inviteMsg);
  network_driver->send(inviteData);

  std::vector<unsigned char> replyData = network_driver->read();
  std::vector<unsigned char> decReply;
  bool valid;
  std::tie(decReply, valid) = crypto_driver->decrypt_and_verify(keys.first, keys.second, replyData);
  if (!valid) throw std::runtime_error("Invalid HMAC on InviteReply");

  UserToAdmin_ReplyMessage replyMsg;
  replyMsg.deserialize(decReply);

  if (replyMsg.accept) {
    cli_driver->print_success(recipientId + " accepted the invite!");
    // send the group info to the recipient
    std::vector<unsigned char> groupStateData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&this->groupState);
    network_driver->send(groupStateData);
  } else {
    cli_driver->print_warning(recipientId + " rejected the invite.");
    return;
  }
  // update GroupState_Message for admin at the end
  this->groupState.members.insert(recipientId);
  AdminToUser_Add_ControlMessage addMsg;
  addMsg.newUserId = recipientId;
  addMsg.groupId = this->groupState.groupId;
  addMsg.adminSignature = this->crypto_driver->RSA_sign(this->RSA_signing_key,concat_string_and_rsakey(this->groupState.groupId, this->groupState.adminVerificationKey));

  for (auto member : this->groupState.members) {
    if (member != this->id) {
      // encrypt addMsg for each member with each member's keys
      auto memberKeys = this->groupState.dhKeyMap[member];
      std::vector<unsigned char> addMsgData = crypto_driver->encrypt_and_tag(memberKeys.first,memberKeys.second,&addMsg);
      // then send the cipher through GenericMessage
      Shignal_GenericMessage maskedAddMsg;
      maskedAddMsg.recipientId = recipientId;
      maskedAddMsg.ciphertext = addMsgData;
      std::vector<unsigned char> maskedAddMsgData;
      maskedAddMsg.serialize(maskedAddMsgData);
      shignal_driver->send(maskedAddMsgData);
    }
  }
}


/**
 * 
 */
/**
 * Handles communicating with another user. This function
 * 1) Prompts the CLI to see if we're registering or logging in.
 * 2) Handles key exchange with the other user.
 */
void UserClient::HandleUser(std::string input) {
  // Handle if connecting or listening; parse user input.
  std::vector<std::string> args = string_split(input, ' ');
  bool isListener = args[0] == "listen";
  if (isListener) {
    if (args.size() != 2) {
      this->cli_driver->print_warning("Invalid args, usage: listen <port>");
      return;
    }
    int port = std::stoi(args[1]);
    this->network_driver->listen(port);
  } else {
    if (args.size() != 3) {
      this->cli_driver->print_warning(
          "Invalid args, usage: connect <ip> <port>");
      return;
    }
    std::string ip = args[1];
    int port = std::stoi(args[2]);
    this->network_driver->connect(ip, port);
    this->shignal_driver->connect("localhost", 2700);
  }

  // Exchange keys.
  auto keys = this->HandleUserKeyExchange();

  // Clear the screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      this->cli_driver->print_warning(
          "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }

    // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    u2u_msg.deserialize(msg_data.first);
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      UserToUser_Message_Message u2u_msg;
      u2u_msg.msg = plaintext;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        this->cli_driver->print_info(
            "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    this->cli_driver->print_right(plaintext);
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
