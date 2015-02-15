/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SBT_CLIENT_HPP
#define SBT_CLIENT_HPP

#include "common.hpp"
#include "meta-info.hpp"
#include "tracker-response.hpp"
#include <map>

namespace sbt {

class Client
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  Client(const std::string& port,
         const std::string& torrent);

  void
  run();

  const std::string&
  getTrackerHost() {
    return m_trackerHost;
  }

  const std::string&
  getTrackerPort() {
    return m_trackerPort;
  }

  const std::string&
  getTrackerFile() {
    return m_trackerFile;
  }
  void connectPeer(sbt::PeerInfo peer);
  void handshake(std::string peerId, int sock);
  void bitfield(int sock);
  void interested(int sock, int index);
  void request(int sock, int index);
  void have(int index, int sock);
  int getMessageLength(char* buf);

  void listenForPeers();
  void acceptHandshake(int sock, std::string peerId);
  void acceptBitfield(int sock);
  void unchoke(int sock);
  void piece(int sock, int index, int begin);
  void acceptHave(int index);

  void
  loadMetaInfo(const std::string& torrent);

  void
  connectTracker();

  void
  sendTrackerRequest();

  void
  recvTrackerResponse();

  MetaInfo m_metaInfo;
  std::string m_trackerHost;
  std::string m_trackerPort;
  std::string m_trackerFile;

  uint16_t m_clientPort;

  int m_trackerSock;
  int m_serverSock = -1;

  fd_set m_readSocks;

  uint64_t m_interval;
  bool m_isFirstReq;
  bool m_isFirstRes;

  std::vector<PeerInfo> m_peers;
  std::map<std::string, int> m_connectedPeers;
  char * m_bitfield;
  int m_bitfield_size;
  int m_num_bits;
  int m_amount_downloaded;
  int m_amount_uploaded;
  char * m_file_byte_array;
};
struct peer_args {
  PeerInfo peerInfo;
  Client* client;
};


} // namespace sbt

#endif // SBT_CLIENT_HPP
