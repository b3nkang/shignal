FROM ubuntu:22.04

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive
ARG TZ=America/New_York
ENV TZ=${TZ}

# Core build and dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  clang \
  cmake \
  git \
  gdb \
  curl \
  nano \
  lldb \
  sudo \
  libboost-all-dev \
  libcrypto++-dev \
  libsqlite3-dev \
  libncurses-dev \
  locales && \
  locale-gen en_US.UTF-8 && \
  rm -rf /var/lib/apt/lists/*

# Set locale
ENV LANG=en_US.UTF-8

# Add non-root user
RUN useradd -m -s /bin/bash shignal-user && \
  echo "shignal-user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/shignal-user

# Switch to user
USER shignal-user
WORKDIR /home/shignal-user

# Default shell
CMD ["/bin/bash"]
