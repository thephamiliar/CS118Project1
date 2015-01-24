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
#include <fstream>
#include "meta-info.hpp"
#include "http/http-request.hpp"
#include "http/http-response.hpp"
#include "tracker-response.hpp"
#include <vector>

namespace sbt {

class Client
{
public: 
  int connectToServer(std::string portNum);
  Client(const std::string& port, const std::string& torrent)
  {
    serverPortNumber = port;
    std::filebuf fb;
    if (fb.open (torrent, std::ios::in)) {

      // decode meta-info
      std::istream is (&fb);
      metaInfo.wireDecode(is);

      fb.close();
      connectToServer(port);

    }
    else {
      std::cout << "you done fucked up";
    } 
  }

  MetaInfo getMetaInfo();
  unsigned short getTrackerPortNumber() {
    return trackerPortNumber;
  }
  std::string getServerPortNumber() {
    return serverPortNumber;
  }
  //int connectToServer
  HttpRequest makeHttpRequest(bool includeEvent);
  void getTrackerInfo();
  void sendTrackerRequest();
private:
  MetaInfo metaInfo;
  unsigned short trackerPortNumber;
  std::string serverPortNumber;
  HttpResponse trackerRes;
  std::vector<PeerInfo> peer_list;
  uint64_t interval;
};

} // namespace sbt

#endif // SBT_CLIENT_HPP
