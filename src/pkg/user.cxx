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
  this->peer_listener_driver = nullptr;
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
  shignal_driver->connect("localhost", 2700);
  this->cli_driver->print_info("Starting signal listener...");
  boost::thread shignalThread = boost::thread(boost::bind(&UserClient::ShignalReceiveThread, this));

  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);

  repl.add_action("invite", "invite <recipientId> <sharedPort>", &UserClient::HandleInviteMember);
  // repl.add_action("join", "join <sharedPort>", &UserClient::HandleJoinGroup);
  repl.add_action("send", "send <message>", &UserClient::HandleSendGroupMessage);
  repl.add_action("login", "login <address> <port>", &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>", &UserClient::HandleLoginOrRegister);
  repl.add_action("listen", "listen <port>", &UserClient::HandleListen);
  repl.add_action("y","y",&UserClient::HandleDummy);
  // repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  // repl.add_action("connect", "connect <address> <port>",
  //                 &UserClient::HandleUser);
  repl.run();
}

void UserClient::HandleDummy(std::string input) {
  this->cli_driver->print_warning("okay we goofed, please give your reply again:");
}


/**
 * Starts listening for a peer connection on a given port.
 */
void UserClient::HandleListen(std::string input) {
  auto args = string_split(input, ' ');
  if (args.size() != 2) {
    this->cli_driver->print_warning("Usage: listen <port>");
    return;
  }

  int port = std::stoi(args[1]);
  auto listener = std::make_shared<NetworkDriverImpl>();

  try {
    listener->prepare_listener(port);
    this->cli_driver->print_success("Listening for peer connections on port " + std::to_string(port));

    std::thread([this, listener]() {
      this->cli_driver->print_info("Waiting for peer connection...");
      try {
        auto peer = listener->accept();
        this->cli_driver->print_success("Received peer connection!");
        auto keys = this->HandleUserKeyExchangeForInvite(peer);
        this->DoJoinGroup(keys,peer);
        this->cli_driver->print_success("END OF HANDLELISTEN!");
        this->cli_driver->print_info("Type your command:");
      } catch (const std::exception &e) {
        this->cli_driver->print_warning("Listener error: " + std::string(e.what()));
      }
    }).detach();

  } catch (const std::exception &e) {
    this->cli_driver->print_warning("Failed to prepare listener: " + std::string(e.what()));
  }
}

/**
 * Lightweight wrapper that does user to user auth KE and then enters DoInviteMember()
 */
void UserClient::HandleInviteMember(std::string input) {
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("Invalid args, usage: invite <userId> <port>");
    return;
  }
  std::string userId = args[1];
  int port = std::stoi(args[2]);

  std::shared_ptr<NetworkDriver> peerDriver = std::make_shared<NetworkDriverImpl>();
  cli_driver->print_info("Attempting to connect on port " + std::to_string(port));
  for (int i = 0; i < 10; ++i) {
    try {
      peerDriver->connect("localhost", port);
      break;
    } catch (const std::runtime_error& e) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
  }
  // peerDriver->connect("localhost", port);
  cli_driver->print_info("Successfully connected on port " + std::to_string(port)+", now attempting KE...");
  auto keys = this->HandleUserKeyExchangeForInvite(peerDriver);
  this->groupState.dhKeyMap[this->id] = {keys.first, keys.second};
  this->cli_driver->print_success("KE completed, connected to " + userId+", now sending invite...");

  this->DoInviteMember(userId, keys, peerDriver);
  this->cli_driver->print_info("End of Invite flow for " + userId);
}

/**
 * Lightweight wrapper that does user to user auth KE and then enters DoJoinGroup()
 */
void UserClient::HandleJoinGroup(std::string input) {
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 2) {
    this->cli_driver->print_warning("Invalid args, usage: join <port>");
    return;
  }
  int port = std::stoi(args[1]);
  this->network_driver->connect("localhost", port);
  this->shignal_driver->connect("localhost", 2700);

  auto keys = this->HandleUserKeyExchange();
  this->cli_driver->print_success("KE completed, connected to admin");

  // this->DoJoinGroup(keys,);
}

/**
 * Lightweight wrapper that parses and calls DoSendGroupMessage()
 */
void UserClient::HandleSendGroupMessage(std::string input) {
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 2) {
    this->cli_driver->print_warning("Invalid args, usage: send <message>");
    return;
  }
  std::string message = args[1];
  this->DoSendGroupMessage(message);
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

  // this->DH_pk = DHpk;
  // this->DH_sk = DHsk;

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

std::pair<SecByteBlock, SecByteBlock>
UserClient::HandleUserKeyExchangeForInvite(std::shared_ptr<NetworkDriver> driver) {
  DH DH_obj;
  SecByteBlock DHsk, DHpk;
  std::tie(DH_obj, DHsk, DHpk) = this->crypto_driver->DH_initialize();

  this->DH_pk = DHpk;
  this->DH_sk = DHsk;

  std::vector<unsigned char> toSign = concat_byteblock_and_cert(DHpk, this->certificate);
  std::string sig = crypto_driver->RSA_sign(this->RSA_signing_key, toSign);

  UserToUser_DHPublicValue_Message msg;
  msg.public_value = DHpk;
  msg.certificate = this->certificate;
  msg.user_signature = sig;

  std::vector<unsigned char> msgData;
  msg.serialize(msgData);
  driver->send(msgData);

  std::vector<unsigned char> recvData = driver->read();
  UserToUser_DHPublicValue_Message incomingMsg;
  incomingMsg.deserialize(recvData);

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
  DHshared = crypto_driver->DH_generate_shared_key(DH_obj, DHsk, incomingMsg.public_value);

  SecByteBlock AESkey = crypto_driver->AES_generate_key(DHshared);
  SecByteBlock HMACkey = crypto_driver->HMAC_generate_key(DHshared);
  return {AESkey, HMACkey};
}


/**
 * Does Authenticated KE between a PrekeyBundle and the user. // login localhost 1234
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleBundleKeyExchange(PrekeyBundle &bundle, std::string memberId) {
  this->cli_driver->print_info("In HandleBundleKeyExchange, with user " +this->id+ " from "+ memberId+"'s bundle");
  // vrfy cert is signed by the server
  std::vector<unsigned char> certData = concat_string_and_rsakey(bundle.senderCert.id, bundle.senderCert.verification_key);
  bool certValid = this->crypto_driver->RSA_verify(this->RSA_server_verification_key, certData, bundle.senderCert.server_signature);
  if (!certValid) {
    throw std::runtime_error("HandlePrekeyBundleExchange: Invalid certificate");
  }
  this->cli_driver->print_success("Certificate verified, now verifying user signature...");
  // sanity check, memberId matches the cert ID
  if (bundle.senderCert.id != memberId) {
    throw std::runtime_error("HandlePrekeyBundleExchange: Certificate ID does not match expected memberId");
  }
  std::vector<unsigned char> userData = concat_byteblock_and_cert(bundle.senderDhPk, bundle.senderCert);
  bool userValid = this->crypto_driver->RSA_verify(bundle.senderCert.verification_key, userData, bundle.senderSignature);
  if (!userValid) {
    throw std::runtime_error("HandlePrekeyBundleExchange: Invalid DH signature from bundle");
  }
  this->cli_driver->print_success("User signature verified, now generating shared key...");

  if (bundle.senderDhPk.SizeInBytes() == 0) {
    throw std::runtime_error("senderDhPk is empty; cannot generate shared key");
  }

  DH DH_obj;
  SecByteBlock DHsk, DHpk;
  std::tie(DH_obj, DHsk, DHpk) = this->crypto_driver->DH_initialize();

  SecByteBlock DHshared(DH_obj.AgreedValueLength());
  DHshared = this->crypto_driver->DH_generate_shared_key(DH_obj, DHsk, bundle.senderDhPk);

  SecByteBlock AESkey = this->crypto_driver->AES_generate_key(DHshared);
  SecByteBlock HMACkey = this->crypto_driver->HMAC_generate_key(DHshared);

  return {AESkey, HMACkey};
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  this->cli_driver->print_info("In HandleLoginOrRegister...");
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
  this->cli_driver->print_success("Registered/logged in as user: " + this->id);
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

  // send notification to ShignalServer that user is online
  if (!this->shignal_driver->connected()) {
    this->cli_driver->print_info("Connecting to Signal server...");
    this->shignal_driver->connect("localhost", 2700);
  }
  UserToShignal_OnlineMessage onlineMsg;
  onlineMsg.userId = this->id;
  std::vector<unsigned char> onlineData;
  onlineMsg.serialize(onlineData);
  this->shignal_driver->send(onlineData);
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
void UserClient::DoInviteMember(std::string recipientId, std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys, std::shared_ptr<NetworkDriver> userDriver) {
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
  this->cli_driver->print_info("Now inside of DoInviteMember workflow..");

  // admin uploads their prekey bundle to the server
  PrekeyBundle bundle;
  bundle.senderSignature = this->crypto_driver->RSA_sign(this->RSA_signing_key,concat_byteblock_and_cert(this->DH_pk,this->certificate));
  bundle.senderDhPk = this->DH_pk;
  this->cli_driver->print_info("current sender dh pk: " + byteblock_to_string(this->DH_pk));
  bundle.senderVk = this->RSA_verification_key;
  bundle.senderCert = this->certificate;

  UserToShignal_PrekeyMessage prekeyMsg;
  prekeyMsg.epochId = this->groupState.epochId;
  prekeyMsg.userId = this->id;
  prekeyMsg.prekeyBundle = bundle;

  this->cli_driver->print_info("Attempting to send prekey bundle to ShignalServer...");
  std::vector<unsigned char> prekeyData;
  prekeyMsg.serialize(prekeyData);
  this->shignal_driver->send(prekeyData);
  this->cli_driver->print_success("Admin bundle sent to ShignalServer.");

  // send the invite message
  AdminToUser_InviteMessage inviteMsg;
  inviteMsg.inviteMsg = "You have been invited to join a group chat! Do you accept?";
  std::vector<unsigned char> inviteData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&inviteMsg);
  userDriver->send(inviteData);
  this->cli_driver->print_info("Invite message sent to " + recipientId);

  std::vector<unsigned char> replyData = userDriver->read();
  std::vector<unsigned char> decReply;
  bool valid;
  std::tie(decReply, valid) = crypto_driver->decrypt_and_verify(keys.first, keys.second, replyData);
  if (!valid) throw std::runtime_error("Invalid HMAC on InviteReply");

  UserToAdmin_ReplyMessage replyMsg;
  replyMsg.deserialize(decReply);
  this->cli_driver->print_info("Received reply from " + recipientId);

  if (replyMsg.accept) {
    cli_driver->print_success(recipientId + " accepted the invite!");
    // send the group info to the recipient
    // importantly, make a clone so that we do not leak Admin dh_keymap to newUser
    GroupState_Message safeGroupState;
    safeGroupState.groupId = this->groupState.groupId;
    safeGroupState.epochId = this->groupState.epochId;
    safeGroupState.adminId = this->groupState.adminId;
    safeGroupState.adminVerificationKey = this->groupState.adminVerificationKey;
    safeGroupState.adminCertificate = this->groupState.adminCertificate;
    safeGroupState.members = this->groupState.members;

    std::vector<unsigned char> safeGroupStateData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&safeGroupState);
    userDriver->send(safeGroupStateData);
  } else {
    cli_driver->print_warning(recipientId + " rejected the invite.");
    return;
  }
  this->cli_driver->print_success("Group info sent to " + recipientId);

  // update GroupState_Message for admin at the end
  this->groupState.members.insert(recipientId);
  AdminToUser_Add_ControlMessage addMsg;
  addMsg.newUserId = recipientId;
  addMsg.groupId = this->groupState.groupId;
  addMsg.adminSignature = this->crypto_driver->RSA_sign(this->RSA_signing_key,concat_string_and_rsakey(this->groupState.groupId, this->groupState.adminVerificationKey));
  this->cli_driver->print_success("Updated admin's local group state, now attempting to send AddControlMessage to all members of the group chat.");

  for (auto member : this->groupState.members) {
    if (member != this->id && member != recipientId) {
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
    } else {
      this->cli_driver->print_info("Skipping sending AddControlMessage to self or new user.");
    }
  }
  // TODO: admin also needs to upload prekey bundle to ShignalServer
  // Admin also needs to poll server to get new user's prekey bundle
}


/**
 * Assumes authenticated KE with given recipientId has already been done.
 * 
 * For the current implementation, Shignal only supports one group chat at a time per user.
 * Therefore if the user is already in a group chat, the user cannot join another group chat.
 */
void UserClient::DoJoinGroup(std::pair<SecByteBlock, SecByteBlock> keys, std::shared_ptr<NetworkDriver> userDriver){
  // check if groupstate is uninitialized
  if (!this->groupState.adminId.empty()) {
    this->cli_driver->print_warning("You are already a group chat. Please leave your current group first.");
    return;
  }
  // read in invite message
  std::vector<unsigned char> inviteData = userDriver->read();
  std::vector<unsigned char> decInvite;
  bool valid;
  std::tie(decInvite, valid) = this->crypto_driver->decrypt_and_verify(keys.first,keys.second,inviteData);
  if (!valid) throw std::runtime_error("Invalid HMAC on invite");

  AdminToUser_InviteMessage inviteMsg;
  inviteMsg.deserialize(decInvite);
  this->cli_driver->print_success(inviteMsg.inviteMsg);

  // prompt user for response
  std::string stdinResponse;
  std::cout << "Accept invite? (y/n): ";
  std::getline(std::cin,stdinResponse);
  bool accept = (stdinResponse == "y");

  // send reply message
  UserToAdmin_ReplyMessage replyMsg;
  replyMsg.accept = accept;
  std::vector<unsigned char> replyData = crypto_driver->encrypt_and_tag(keys.first,keys.second,&replyMsg);
  userDriver->send(replyData);

  if (!accept) { // short circuit if user rejects
    this->cli_driver->print_info("You rejected the group invite.");
    return;
  }

  // read in group info
  std::vector<unsigned char> groupStateData = userDriver->read();
  std::vector<unsigned char> decGroupState;
  bool valid2;
  std::tie(decGroupState, valid2) = this->crypto_driver->decrypt_and_verify(keys.first,keys.second,groupStateData);
  if (!valid2) throw std::runtime_error("Invalid HMAC on groupState");
  GroupState_Message groupStateMsg;
  groupStateMsg.deserialize(decGroupState);
  this->groupState = groupStateMsg;
  this->cli_driver->print_success("You have joined the group chat!");

  // send prekey bundle to ShigalServer
  PrekeyBundle bundle;
  bundle.senderSignature = this->crypto_driver->RSA_sign(this->RSA_signing_key,concat_byteblock_and_cert(this->DH_pk,this->certificate));
  bundle.senderDhPk = this->DH_pk;
  bundle.senderVk = this->RSA_verification_key;
  bundle.senderCert = this->certificate;


  UserToShignal_PrekeyMessage prekeyMsg;
  prekeyMsg.epochId = this->groupState.epochId;
  prekeyMsg.userId = this->id;
  prekeyMsg.prekeyBundle = bundle;

  this->cli_driver->print_info("Attempting to send prekey bundle to ShignalServer...");
  std::vector<unsigned char> prekeyData;
  prekeyMsg.serialize(prekeyData);
  this->shignal_driver->send(prekeyData);
  this->cli_driver->print_success("Prekey bundle sent to ShignalServer.");

  // do auth KE for all members' prekeys in current epoch
  for (auto memberId : this->groupState.members) {
    if (memberId != this->id) {
      UserToShignal_RequestPrekeyBundle prekeyReq;
      prekeyReq.epochId = this->groupState.epochId;
      prekeyReq.requestedId = memberId;
      prekeyReq.requestorId = this->id;
      std::vector<unsigned char> prekeyReqData;
      prekeyReq.serialize(prekeyReqData);
      this->shignal_driver->send(prekeyReqData);
      this->cli_driver->print_success("Sent prekey request to ShignalServer for " + memberId);

      // wait for prekey bundle response
      // std::vector<unsigned char> respData = this->shignal_driver->read();
      // this->cli_driver->print_success("Received prekey bundle from ShignalServer for " + memberId);
      // this->cli_driver->print_info("DOJOINGROUP: Received Shignal message of type " + std::to_string(respData[0]));
      // while (respData[0] != MessageType::ShignalToUser_PrekeyBundleResponse) {
      //   this->cli_driver->print_warning("DOJOINGROUP: wrong messageType received.");
      //   this->cli_driver->print_info("DOJOINGROUP: listening again...");
      //   respData = this->shignal_driver->read();
      // }      
      std::unique_lock<std::mutex> lock(shignalMtx);
      shignalCondVar.wait(lock, [&]() {
        return !shignalPrekeyResponses.empty();
      });
      std::vector<unsigned char> respData = shignalPrekeyResponses.front();
      shignalPrekeyResponses.pop_front();

      ShignalToUser_PrekeyBundleResponse prekeyResp;
      prekeyResp.deserialize(respData);
      int retries = 0;
      // poll retries up to 5 times if prekey not found
      while (!prekeyResp.found && retries < 5) {
        this->cli_driver->print_warning("Prekey not found for new user " + memberId + ". Retrying...");
        this->cli_driver->print_info("DOJOINGROUP: ABORTING IN POLL RETRY");
        // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        // prekeyReq.epochId = this->groupState.epochId;
        // prekeyReq.requestedId = memberId;
        // prekeyReq.requestorId = this->id;

        // std::vector<unsigned char> reqData;
        // prekeyReq.serialize(reqData);
        // this->shignal_driver->send(reqData);

        // respData = this->shignal_driver->read();
        // prekeyResp.deserialize(respData);
        // retries++;
      }
      if (!prekeyResp.found) {
        this->cli_driver->print_warning("Prekey not found for " + memberId + ". Skipping KE.");
        continue;
      }
      this->cli_driver->print_success("Prekey bundle found for " + memberId + ", now doing KE...");
      // do authenticated KE with the prekey bundle
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = this->HandleBundleKeyExchange(prekeyResp.prekeyBundle, memberId);
      // store the keys in the dhKeyMap
      this->groupState.dhKeyMap[memberId] = keys;
      this->cli_driver->print_success("Authenticated KE with " + memberId);
    }
  }
}

/**
 * A megahandler for receiving messages from the ShignalServer.
 */
void UserClient::HandleShignalMessage(std::vector<unsigned char> data) {
  // deserialize the masked msg
  this->cli_driver->print_info("HANDLESHIGNALMSG: recvd message of type " + std::to_string(data[0]));

  if (data[0] != MessageType::Shignal_GenericMessage) {
    this->cli_driver->print_warning("Invalid Shignal message received.");
    return;
  }

  Shignal_GenericMessage maskedMsg;
  maskedMsg.deserialize(data);

  // make sure we have keys for the recipient and get them
  if (!this->groupState.dhKeyMap.contains(maskedMsg.recipientId)) {
    this->cli_driver->print_warning("Received message for unknown recipient: " + maskedMsg.recipientId);
    return;
  }
  auto [aesKey, hmacKey] = this->groupState.dhKeyMap.at(maskedMsg.recipientId);

  // dec and vrfy
  std::vector<unsigned char> decMsg;
  bool valid;
  std::tie(decMsg,valid) = this->crypto_driver->decrypt_and_verify(aesKey, hmacKey, maskedMsg.ciphertext);
  if (!valid) {
    this->cli_driver->print_warning("Invalid MAC on Shignal message from " + maskedMsg.recipientId);
    return;
  }

  if (decMsg.empty()) {
    this->cli_driver->print_warning("Empty message received, ending handling of ShignalMessage");
    return;
  }

  if (decMsg[0] == MessageType::MessagePayload) {
    // this is a normal message, handle normally
    HandleMessagePayload(decMsg);
  } else if (decMsg[0] == MessageType::AdminToUser_Add_ControlMessage) {
    // this is a control message, handle
    HandleAddControlMessage(decMsg);
  } else {
    this->cli_driver->print_warning("Unknown message type received from " + maskedMsg.recipientId+". Exiting handling of ShignalMessage.");
    return;
  }
}

// =========================================================
// HANDLERS FOR DIFFERENT GENERIC SHIGNAL MESSAGES
// =========================================================

/**
 * Handles a decrypted Shignal_GenericMessage whose cipher is a MessagePayload.
 */
void UserClient::HandleMessagePayload(std::vector<unsigned char> decMsg) {
  MessagePayload msg;
  msg.deserialize(decMsg);
  this->cli_driver->print_success("From " + msg.senderId + ": " + msg.msgContent);
}

/**
 * Handles a decrypted AdminToUser_Add_ControlMessage.
 */
void UserClient::HandleAddControlMessage(std::vector<unsigned char> decMsg) {
  AdminToUser_Add_ControlMessage msg;
  msg.deserialize(decMsg);
  
  // vrfy admin signature
  std::vector<unsigned char> signedData = concat_string_and_rsakey(this->groupState.groupId, this->groupState.adminVerificationKey);
  bool valid = this->crypto_driver->RSA_verify(this->groupState.adminVerificationKey, signedData, msg.adminSignature);
  if (!valid) {
    this->cli_driver->print_warning("Invalid admin signature on Add_ControlMessage");
    return;
  }
  this->cli_driver->print_success("Verified Add_ControlMessage for new user: " + msg.newUserId);

  // get prekey from ShignalServer
  UserToShignal_RequestPrekeyBundle prekeyReq;
  prekeyReq.epochId = this->groupState.epochId;
  prekeyReq.requestedId = msg.newUserId;
  prekeyReq.requestorId = this->id;

  std::vector<unsigned char> reqData;
  prekeyReq.serialize(reqData);
  this->shignal_driver->send(reqData);

  std::unique_lock<std::mutex> lock(shignalMtx);
  shignalCondVar.wait(lock, [&]() {
    return !shignalPrekeyResponses.empty();
  });
  std::vector<unsigned char> respData = shignalPrekeyResponses.front();
  shignalPrekeyResponses.pop_front();

  ShignalToUser_PrekeyBundleResponse prekeyResp;
  prekeyResp.deserialize(respData);

  int retries = 0;
  while (!prekeyResp.found && retries < 5) {
    this->cli_driver->print_warning("Prekey not found for new user " + msg.newUserId + ". Retrying...");
    this->cli_driver->print_info("handleADDCONTROLMESSAGE: ABORTING IN POLL RETRY");
    // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    // prekeyReq.epochId = this->groupState.epochId;
    // prekeyReq.requestedId = msg.newUserId;
    // prekeyReq.requestorId = this->id;

    // std::vector<unsigned char> reqData;
    // prekeyReq.serialize(reqData);
    // this->shignal_driver->send(reqData);

    // respData = this->shignal_driver->read();
    // prekeyResp.deserialize(respData);
    // retries++;
  }
  if (!prekeyResp.found) {
    this->cli_driver->print_warning("Prekey not found for new user " + msg.newUserId + ". Exiting.");
    return;
  }

  // atp we must have the prekey, now do authenticated KE
  auto keys = this->HandleBundleKeyExchange(prekeyResp.prekeyBundle, msg.newUserId);
  this->groupState.dhKeyMap[msg.newUserId] = keys;
  // add the new user to the group state
  this->groupState.members.insert(msg.newUserId);

  this->cli_driver->print_success("Completed authenticated KE with new user " + msg.newUserId);
}

// =================================================================
// FUNCTIONS FOR SEND MESSAGE DIAGRAM WORKFLOW START BELOW
// =================================================================

void UserClient::DoSendGroupMessage(std::string message) {
  // check if groupstate is uninitialized
  if (this->groupState.adminId.empty()) {
    this->cli_driver->print_warning("You are not in a group chat. Please create a group chat first.");
    return;
  }
  for (auto memberId : this->groupState.members) {
    if (memberId != this->id) {
      auto memberKeys = this->groupState.dhKeyMap[memberId];
      MessagePayload messagePayload;
      messagePayload.msgContent = message;
      messagePayload.groupId = this->groupState.groupId;
      messagePayload.senderId = this->id;
      std::vector<unsigned char> msgData = crypto_driver->encrypt_and_tag(memberKeys.first,memberKeys.second,&messagePayload);
      // then send the cipher through GenericMessage
      Shignal_GenericMessage maskedMsg;
      maskedMsg.recipientId = memberId;
      maskedMsg.ciphertext = msgData;
      std::vector<unsigned char> maskedMsgData;
      maskedMsg.serialize(maskedMsgData);
      shignal_driver->send(maskedMsgData);
      this->cli_driver->print_success("Sent message to " + memberId);
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

  // TODO: don't forget we need to save the keys in the dh_keymap once we have it

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
 * Listen for messages and print to CLI.
 */
void UserClient::ShignalReceiveThread() {
  while (true) {
    std::vector<unsigned char> data;

    try {
      data = this->shignal_driver->read();
      this->cli_driver->print_info("Received data from ShignalServer");
    } catch (const std::runtime_error &e) {
      this->cli_driver->print_warning("Signal server connection closed or read failed.");
      return;
    }

    if (data.size() > 0 && data[0] == MessageType::ShignalToUser_PrekeyBundleResponse) {
      std::lock_guard<std::mutex> lock(shignalMtx);
      shignalPrekeyResponses.push_back(data);
      shignalCondVar.notify_all();
    } else {
      try {
        this->cli_driver->print_info("Delegating message to HandleShignalMessage...");
        this->HandleShignalMessage(data);
        this->cli_driver->print_info("Finished handling Shignal message");
      } catch (const std::exception &e) {
        this->cli_driver->print_warning("Failed to handle Shignal message: " + std::string(e.what()));
      }
    }
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
