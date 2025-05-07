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
  std::thread listener_thread(&ShignalServerClient::ListenForMessages, this, this->port);
  listener_thread.detach();

  REPLDriver<ShignalServerClient> repl = REPLDriver<ShignalServerClient>(this);
  // repl.add_action("online", "show online users", &SignalServerClient::ShowOnlineUsers);
  repl.run();
}

void ShignalServerClient::ListenForMessages() {
  while (true) {
    std::shared_ptr<NetworkDriver> driver = std::make_shared<NetworkDriverImpl>();
    driver->listen(this->port);
    std::thread(&ShignalServerClient::HandleShignalMessage, this, driver).detach();
  }
}

void ShignalServerClient::HandleShignalMessage(std::shared_ptr<NetworkDriver> driver) {
  std::vector<unsigned char> data = driver->read();
  unsigned char msgType = data[0]; 

  switch (msgType) {
    case MessageType::Shignal_GenericMessage:
      this->cli_driver->print_info("Shignal received Shignal_GenericMessage, handling...");
      HandleGenericMessage(data);
      break;
    case MessageType::PrekeyBundle:
      this->cli_driver->print_info("Shignal received PrekeyBundle, handling...");
      HandlePrekeyBundle(data);
      break;
    case MessageType::UserToShignal_OnlineMessage:
      this->cli_driver->print_info("Shignal received UserToShignal_OnlineMessage, handling...");
      HandleOnlineMessage(data,driver);
      break;
    default:
      this->cli_driver->print_warning("Unknown message type received.");
      break;
  }

  driver->disconnect();
}
