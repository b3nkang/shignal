#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"
#include "../../include/pkg/shignalServer.hpp"

using namespace boost::asio::ip;

int main() {
  ShignalServerClient shignal;
  shignal.run();
  return 0;
}
