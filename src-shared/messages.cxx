#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SHIGNAL MESSAGE SERIALIZERS AND DESERIALIZERS
// ================================================

/**
 * serialize Shignal_GenericMessage.
 */
void Shignal_GenericMessage::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::Shignal_GenericMessage);
  
  // Add fields in order
  put_string(this->senderId, data);
  put_string(this->recipientId, data);
  
  // For ciphertext (which is a vector<unsigned char>)
  std::string ciphertext_str = chvec2str(this->ciphertext);
  put_string(ciphertext_str, data);
}

/**
 * deserialize Shignal_GenericMessage.
 */
int Shignal_GenericMessage::deserialize(std::vector<unsigned char> &data) {
  // Check message type
  assert(data[0] == MessageType::Shignal_GenericMessage);
  
  // Get fields in same order
  int n = 1;
  
  std::string ciphertext_str;
  n += get_string(&this->senderId, data, n);
  n += get_string(&this->recipientId, data, n);
  n += get_string(&ciphertext_str, data, n);
  
  // Convert ciphertext back to vector
  this->ciphertext = str2chvec(ciphertext_str);
  
  return n;
}

/**
 * serialize UserToShignal_OnlineMessage.
 */
void UserToShignal_OnlineMessage::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::UserToShignal_OnlineMessage);
  
  // Add fields in order
  put_string(this->userId, data);
}

/**
 * deserialize UserToShignal_OnlineMessage.
 */
int UserToShignal_OnlineMessage::deserialize(std::vector<unsigned char> &data) {
  // Check message type
  assert(data[0] == MessageType::UserToShignal_OnlineMessage);
  
  // Get fields in same order
  int n = 1;
  n += get_string(&this->userId, data, n);
  
  return n;
}

/**
 * serialize Shignal_PrekeyMessage.
 */
void UserToShignal_PrekeyMessage::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::UserToShignal_PrekeyMessage);
  
  // Add fields in order
  put_string(this->epochId, data);
  put_string(this->userId, data);
  
  // Serialize the bundle
  std::vector<unsigned char> prekeyData;
  this->prekeyBundle.serialize(prekeyData);
  data.insert(data.end(), prekeyData.begin(), prekeyData.end());
}

/**
 * deserialize Shignal_PrekeyMessage.
 */
int UserToShignal_PrekeyMessage::deserialize(std::vector<unsigned char> &data) {
    // Check message type
    assert(data[0] == MessageType::UserToShignal_PrekeyMessage);
    
    // Get fields in same order
    int n = 1;
    
    n += get_string(&this->epochId, data, n);
    n += get_string(&this->userId, data, n);
    
    // Deserialize the bundle
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    int bundle_bytes = this->prekeyBundle.deserialize(slice);
    n += bundle_bytes;
    
    return n;
}

/**
 * serialize UserToShignal_RequestPrekeyBundle.
 */
void UserToShignal_RequestPrekeyBundle::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::UserToShignal_RequestPrekeyBundle);

  // Add fields in order
  put_string(this->epochId, data);
  put_string(this->requestedId, data);
  put_string(this->requestorId, data);
}

/**
 * deserialize UserToShignal_RequestPrekeyBundle.
 */
int UserToShignal_RequestPrekeyBundle::deserialize(std::vector<unsigned char> &data) {
  // Check message type
  assert(data[0] == MessageType::UserToShignal_RequestPrekeyBundle);

  // Get fields in same order
  int n = 1;
  n += get_string(&this->epochId, data, n);
  n += get_string(&this->requestedId, data, n);
  n += get_string(&this->requestorId, data, n);

  return n;
}

/**
 * serialize ShignalToUser_PrekeyBundleResponse.
 */
void ShignalToUser_PrekeyBundleResponse::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::ShignalToUser_PrekeyBundleResponse);

  // Add fields in order
  put_bool(this->found, data);
  
  // Serialize the bundle
  std::vector<unsigned char> prekeyData;
  this->prekeyBundle.serialize(prekeyData);
  data.insert(data.end(), prekeyData.begin(), prekeyData.end());
}

/**
 * deserialize ShignalToUser_PrekeyBundleResponse.
 */
int ShignalToUser_PrekeyBundleResponse::deserialize(std::vector<unsigned char> &data) {
  // Check message type
  assert(data[0] == MessageType::ShignalToUser_PrekeyBundleResponse);

  // Get fields in same order
  int n = 1;
  n += get_bool(&this->found, data, n);
  
  // Deserialize the bundle
  std::vector<unsigned char> slice(data.begin() + n, data.end());
  int bundle_bytes = this->prekeyBundle.deserialize(slice);
  n += bundle_bytes;

  return n;
}

/**
 * serialize PrekeyBundle.
 */
void PrekeyBundle::serialize(std::vector<unsigned char> &data) {
  // Add message type
  data.push_back((char)MessageType::PrekeyBundle);

  // Add fields in order
  put_string(this->senderSignature, data);

  std::string senderDhPk_str = byteblock_to_string(this->senderDhPk);
  put_string(senderDhPk_str, data);

  std::string senderVk_str;
  CryptoPP::StringSink ss(senderVk_str);
  this->senderVk.Save(ss);
  put_string(senderVk_str, data);

  std::vector<unsigned char> certificate_data;
  this->senderCert.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());
}

/**
 * deserialize PrekeyBundle.
 */
int PrekeyBundle::deserialize(std::vector<unsigned char> &data) {
  int n = 1;
  n += get_string(&this->senderSignature, data, n);

  std::string dh_pk_str;
  n += get_string(&dh_pk_str, data, n);
  this->senderDhPk = string_to_byteblock(dh_pk_str);

  std::string senderVk_str;
  n += get_string(&senderVk_str, data, n);
  CryptoPP::StringSource ss(senderVk_str, true);
  this->senderVk.Load(ss);

  std::vector<unsigned char> slice = std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->senderCert.deserialize(slice);

  return n;
}

/**
 * serialize MessagePayload.
 */
void MessagePayload::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::MessagePayload);

  put_string(this->msgContent, data);
  put_string(this->groupId, data);
  put_string(this->senderId, data);
}

/**
 * deserialize MessagePayload.
 */
int MessagePayload::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::MessagePayload);
  
  int n = 1;
  n += get_string(&this->msgContent, data, n);
  n += get_string(&this->groupId, data, n);
  n += get_string(&this->senderId, data, n);
  return n;
}

// ================================================
// GROUP STATE MESSAGE SERIALIZER AND DESERIALIZER
// ================================================

// TODO: make sure this is correct, very sus implementation
/**
 * serialize GroupState_Message.
 */
void GroupState_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::GroupState_Message);

  put_string(this->groupId, data);
  put_string(this->epochId, data);

  // Serialize members set
  put_integer(CryptoPP::Integer(this->members.size()), data);
  for (const std::string &member : this->members) {
    put_string(member, data);
  }

  // Serialize dhKeyMap
  put_integer(CryptoPP::Integer(this->dhKeyMap.size()), data);
  for (const auto &entry : this->dhKeyMap) {
    put_string(entry.first, data);
    put_string(byteblock_to_string(entry.second.first), data);
    put_string(byteblock_to_string(entry.second.second), data);
  }

  // Serialize admin info
  put_string(this->adminId, data);

  std::string adminVkStr;
  CryptoPP::StringSink ss(adminVkStr);
  this->adminVerificationKey.Save(ss);
  put_string(adminVkStr, data);

  std::vector<unsigned char> cert_data;
  this->adminCertificate.serialize(cert_data);
  data.insert(data.end(), cert_data.begin(), cert_data.end());
}

/**
 * deserialize GroupState_Message.
 */
int GroupState_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::GroupState_Message);
  int n = 1;

  n += get_string(&this->groupId, data, n);
  n += get_string(&this->epochId, data, n);

  // Deserialize members
  CryptoPP::Integer set_size;
  n += get_integer(&set_size, data, n);
  this->members.clear();
  for (size_t i = 0; i < set_size.ConvertToLong(); ++i) {
    std::string member;
    n += get_string(&member, data, n);
    this->members.insert(member);
  }

  // Deserialize dhKeyMap
  CryptoPP::Integer map_size;
  n += get_integer(&map_size, data, n);
  this->dhKeyMap.clear();
  for (size_t i = 0; i < map_size.ConvertToLong(); ++i) {
    std::string userId, aes_str, hmac_str;
    n += get_string(&userId, data, n);
    n += get_string(&aes_str, data, n);
    n += get_string(&hmac_str, data, n);
    this->dhKeyMap[userId] = {
      string_to_byteblock(aes_str),
      string_to_byteblock(hmac_str)
    };
  }

  n += get_string(&this->adminId, data, n);

  std::string adminVkStr;
  n += get_string(&adminVkStr, data, n);
  CryptoPP::StringSource ss(adminVkStr, true);
  this->adminVerificationKey.Load(ss);

  std::vector<unsigned char> slice(data.begin() + n, data.end());
  int cert_bytes = this->adminCertificate.deserialize(slice);
  n += cert_bytes;

  return n;
}

// ================================================
// INVITATION MESSAGE SERIALIZERS AND DESERIALIZERS
// ================================================

/**
 * serialize AdminToUser_InviteMessage.
 */
void AdminToUser_InviteMessage::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::AdminToUser_InviteMessage);
  put_string(this->inviteMsg, data);
}

/**
 * deserialize AdminToUser_InviteMessage.
 */
int AdminToUser_InviteMessage::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::AdminToUser_InviteMessage);

  int n = 1;
  n += get_string(&this->inviteMsg, data, n);
  return n;
}

/**
 * serialize UserToAdmin_ReplyMessage.
 */
void UserToAdmin_ReplyMessage::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToAdmin_ReplyMessage);
  put_bool(this->accept, data);
}

/**
 * deserialize UserToAdmin_ReplyMessage.
 */
int UserToAdmin_ReplyMessage::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToAdmin_ReplyMessage); 

  int n = 1;
  n += get_bool(&this->accept, data, n);
  return n;
}

// ================================================
// CONTROL MESSAGE SERIALIZERS AND DESERIALIZERS
// ================================================

/**
 * serialize AdminToUser_ControlMessage.
 */ 
void AdminToUser_Add_ControlMessage::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::AdminToUser_Add_ControlMessage);
  put_string(this->newUserId, data);
  put_string(this->groupId, data);
  put_string(this->adminSignature, data);
}

/**
 * deserialize AdminToUser_ControlMessage.
 */
int AdminToUser_Add_ControlMessage::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::AdminToUser_Add_ControlMessage);
  int n = 1;
  n += get_string(&this->newUserId, data, n);
  n += get_string(&this->groupId, data, n);
  n += get_string(&this->adminSignature, data, n);
  return n;
}

// ================================================
// ALL OTHER PROVIDED SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the next bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the next string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

/**
 * serialize Certificate_Message.
 */
void Certificate_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Certificate_Message);

  // Serialize signing key.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);

  // Add fields.
  put_string(this->id, data);
  put_string(verification_key_str, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize Certificate_Message.
 */
int Certificate_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Certificate_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&verification_key_str, data, n);
  n += get_string(&this->server_signature, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  return n;
}

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  put_string(server_public_string, data);

  std::string user_public_string = byteblock_to_string(this->user_public_value);
  put_string(user_public_string, data);

  put_string(this->server_signature, data);
}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  int n = 1;
  std::string server_public_string;
  n += get_string(&server_public_string, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);

  std::string user_public_string;
  n += get_string(&user_public_string, data, n);
  this->user_public_value = string_to_byteblock(user_public_string);

  n += get_string(&this->server_signature, data, n);
  return n;
}

/**
 * serialize UserToServer_IDPrompt_Message.
 */
void UserToServer_IDPrompt_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_IDPrompt_Message);

  // Add fields.
  put_string(this->id, data);
  put_bool(this->new_user, data);
}

/**
 * deserialize UserToServer_IDPrompt_Message.
 */
int UserToServer_IDPrompt_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_IDPrompt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_bool(&this->new_user, data, n);
  return n;
}

/**
 * serialize ServerToUser_Salt_Message.
 */
void ServerToUser_Salt_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_Salt_Message);

  // Add fields.
  put_string(this->salt, data);
}

/**
 * deserialize ServerToUser_Salt_Message.
 */
int ServerToUser_Salt_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_Salt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->salt, data, n);
  return n;
}

/**
 * serialize UserToServer_HashedAndSaltedPassword_Message.
 */
void UserToServer_HashedAndSaltedPassword_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back(
      (char)MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Add fields.
  put_string(this->hspw, data);
}

/**
 * deserialize UserToServer_HashedAndSaltedPassword_Message.
 */
int UserToServer_HashedAndSaltedPassword_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->hspw, data, n);
  return n;
}

/**
 * serialize ServerToUser_PRGSeed_Message.
 */
void ServerToUser_PRGSeed_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_PRGSeed_Message);

  // Add fields.
  std::string seed_string = byteblock_to_string(this->seed);
  put_string(seed_string, data);
}

/**
 * deserialize ServerToUser_PRGSeed_Message.
 */
int ServerToUser_PRGSeed_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_PRGSeed_Message);

  // Get fields.
  std::string seed_string;
  int n = 1;
  n += get_string(&seed_string, data, n);
  this->seed = string_to_byteblock(seed_string);
  return n;
}

/**
 * serialize UserToServer_PRGValue_Message.
 */
void UserToServer_PRGValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_PRGValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->value);
  put_string(value_string, data);
}

/**
 * deserialize UserToServer_PRGValue_Message.
 */
int UserToServer_PRGValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_PRGValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->value = string_to_byteblock(value_string);
  return n;
}

void UserToServer_VerificationKey_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_VerificationKey_Message);

  // Add fields.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);
  put_string(verification_key_str, data);
}

int UserToServer_VerificationKey_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_VerificationKey_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&verification_key_str, data, n);

  // Deserialize key
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);

  return n;
}

/**
 * serialize ServerToUser_IssuedCertificate_Message.
 */
void ServerToUser_IssuedCertificate_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_IssuedCertificate_Message);

  // Add fields.
  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());
}

/**
 * deserialize ServerToUser_IssuedCertificate_Message.
 */
int ServerToUser_IssuedCertificate_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_IssuedCertificate_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  return n;
}

// ================================================
// USER <=> USER MESSAGES
// ================================================

/**
 * serialize UserToUser_DHPublicValue_Message.
 */
void UserToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_DHPublicValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->public_value);
  put_string(value_string, data);

  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());

  put_string(this->user_signature, data);
}

/**
 * deserialize UserToUser_DHPublicValue_Message.
 */
int UserToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_DHPublicValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->public_value = string_to_byteblock(value_string);

  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  n += get_string(&this->user_signature, data, n);
  return n;
}

/**
 * serialize UserToUser_Message_Message.
 */
void UserToUser_Message_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_Message_Message);

  // Add fields.
  put_string(this->msg, data);
}

/**
 * deserialize UserToUser_Message_Message.
 */
int UserToUser_Message_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_Message_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->msg, data, n);
  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate a string and a RSA public key into vector of unsigned char
 */
std::vector<unsigned char>
concat_string_and_rsakey(std::string &s, CryptoPP::RSA::PublicKey &k) {
  // Concat s to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), s.begin(), s.end());

  // Concat k to vec
  std::string k_str;
  CryptoPP::StringSink ss(k_str);
  k.Save(ss);
  v.insert(v.end(), k_str.begin(), k_str.end());
  return v;
}

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a byteblock and certificate into vector of unsigned char
 */
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          Certificate_Message &cert) {
  // Convert byteblock to strings, serialize cert
  std::string b_str = byteblock_to_string(b);

  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  // Concat string and data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), b_str.begin(), b_str.end());
  v.insert(v.end(), cert_data.begin(), cert_data.end());
  return v;
}