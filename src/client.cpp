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

#include "client.hpp"
#include "tracker-request-param.hpp"
#include "tracker-response.hpp"
#include "http/http-request.hpp"
#include "http/http-response.hpp"
#include <fstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <map>
#include <pthread.h>

#include "msg/handshake.hpp"
#include "msg/msg-base.hpp"
#include "util/buffer-stream.hpp"
#include "util/hash.hpp"
namespace sbt {

Client::Client(const std::string& port, const std::string& torrent)
  : m_interval(3600)
  , m_isFirstReq(true)
  , m_isFirstRes(true)
{
  srand(time(NULL));

  m_clientPort = boost::lexical_cast<uint16_t>(port);

  loadMetaInfo(torrent);
  m_amount_downloaded = 0;
  m_amount_uploaded = 0;
  run();
}

void
Client::run()
{
  pthread_t peer;
  struct sbt::peer_args *args; 
  do {
    connectTracker();
    sendTrackerRequest();
    recvTrackerResponse();
    if (m_isFirstReq) {
      int64_t file_length = m_metaInfo.getLength();
      std::cout << file_length << std::endl;
      int64_t piece_length = m_metaInfo.getPieceLength();
      std::vector<uint8_t> pieces = m_metaInfo.getPieces();
      int num_bits = file_length / piece_length;
      if (file_length % piece_length != 0) {
        num_bits++;
      }
      int num_bytes = num_bits/8;
      if (num_bytes % 8 != 0) {
        num_bytes++;
      }
      m_bitfield = (char *) malloc(num_bytes);
      memset(m_bitfield, 0, num_bytes);
 
      m_bitfield_size = num_bytes;
      m_num_bits = num_bits;
      m_file_byte_array = (char *) malloc(m_num_bits*m_metaInfo.getPieceLength());
    }

    m_isFirstReq = false;
    for (auto it = m_peers.begin()+1; it != m_peers.end(); it++) {
      if(m_connectedPeers.find(it->peerId) == m_connectedPeers.end()) {
        args = (struct sbt::peer_args*)malloc(sizeof(struct sbt::peer_args));
        args->peerInfo = *it;
        args->client = this;
        pthread_create(&peer,NULL, connectPeer, args);
      }
    }
    std::cout << "about to sleep" << std::endl;
    std::cout <<"interval: " <<m_interval << std::endl;
    close(m_trackerSock);
    sleep(m_interval+5);
  } while(m_amount_downloaded < m_metaInfo.getLength());
  std::cout << "finished downloading" <<std::endl;

  std::ofstream stream;
  stream.open("text.txt", std::ofstream::out);
  stream << m_file_byte_array;
}

void
Client::loadMetaInfo(const std::string& torrent)
{
  std::ifstream is(torrent);
  m_metaInfo.wireDecode(is);

  std::string announce = m_metaInfo.getAnnounce();
  std::string url;
  std::string defaultPort;
  if (announce.substr(0, 5) == "https") {
    url = announce.substr(8);
    defaultPort = "443";
  }
  else if (announce.substr(0, 4) == "http") {
    url = announce.substr(7);
    defaultPort = "80";
  }
  else
    throw Error("Wrong tracker url, wrong scheme");

  size_t slashPos = url.find('/');
  if (slashPos == std::string::npos) {
    throw Error("Wrong tracker url, no file");
  }
  m_trackerFile = url.substr(slashPos);

  std::string host = url.substr(0, slashPos);

  size_t colonPos = host.find(':');
  if (colonPos == std::string::npos) {
    m_trackerHost = host;
    m_trackerPort = defaultPort;
  }
  else {
    m_trackerHost = host.substr(0, colonPos);
    m_trackerPort = host.substr(colonPos + 1);
  }
}

void
Client::connectTracker()
{
  m_trackerSock = socket(AF_INET, SOCK_STREAM, 0);

  struct addrinfo hints;
  struct addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; // IPv4
  hints.ai_socktype = SOCK_STREAM;

  // get address
  int status = 0;
  if ((status = getaddrinfo(m_trackerHost.c_str(), m_trackerPort.c_str(), &hints, &res)) != 0)
    throw Error("Cannot resolver tracker ip");

  struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
  char ipstr[INET_ADDRSTRLEN] = {'\0'};
  inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
  // std::cout << "tracker address: " << ipstr << ":" << ntohs(ipv4->sin_port) << std::endl;

  if (connect(m_trackerSock, res->ai_addr, res->ai_addrlen) == -1) {
    perror("connect");
    throw Error("Cannot connect tracker");
  }

  freeaddrinfo(res);
}

void
Client::sendTrackerRequest()
{
  TrackerRequestParam param;

  param.setInfoHash(m_metaInfo.getHash());
  param.setPeerId("SIMPLEBT.TEST.PEERID"); //TODO:
  param.setIp("127.0.0.1"); //TODO:
  param.setPort(m_clientPort); //TODO:
 if (m_isFirstReq)
    param.setEvent(TrackerRequestParam::STARTED);
  else {
    param.setUploaded(m_amount_uploaded); //TODO:
    param.setDownloaded(m_amount_downloaded); //TODO:
    param.setLeft(m_metaInfo.getLength() - m_amount_downloaded); //TODO:
  }
  //std::string path = m_trackerFile;
  std::string path = m_metaInfo.getAnnounce();
  path += param.encode();

  HttpRequest request;
  request.setMethod(HttpRequest::GET);
  request.setHost(m_trackerHost);
  request.setPort(boost::lexical_cast<uint16_t>(m_trackerPort));
  request.setPath(path);
  request.setVersion("1.0");

  Buffer buffer(request.getTotalLength());

  request.formatRequest(reinterpret_cast<char *>(buffer.buf()));

  send(m_trackerSock, buffer.buf(), buffer.size(), 0);
}

void
Client::recvTrackerResponse()
{
  std::stringstream headerOs;
  std::stringstream bodyOs;

  char buf[512] = {0};
  char lastTree[3] = {0};

  bool hasEnd = false;
  bool hasParseHeader = false;
  HttpResponse response;

  uint64_t bodyLength = 0;

  while (true) {
    memset(buf, '\0', sizeof(buf));
    memcpy(buf, lastTree, 3);

    ssize_t res = recv(m_trackerSock, buf + 3, 512 - 3, 0);

    if (res == -1) {
      perror("recv");
      return;
    }

    const char* endline = 0;

    if (!hasEnd)
      endline = (const char*)memmem(buf, res, "\r\n\r\n", 4);

    if (endline != 0) {
      const char* headerEnd = endline + 4;

      headerOs.write(buf + 3, (endline + 4 - buf - 3));

      if (headerEnd < (buf + 3 + res)) {
        bodyOs.write(headerEnd, (buf + 3 + res - headerEnd));
      }

      hasEnd = true;
    }
    else {
      if (!hasEnd) {
        memcpy(lastTree, buf + res, 3);
        headerOs.write(buf + 3, res);
      }
      else
        bodyOs.write(buf + 3, res);
    }

    if (hasEnd) {
      if (!hasParseHeader) {
        response.parseResponse(headerOs.str().c_str(), headerOs.str().size());
        hasParseHeader = true;

        bodyLength = boost::lexical_cast<uint64_t>(response.findHeader("Content-Length"));
      }
    }

    if (hasParseHeader && bodyOs.str().size() >= bodyLength)
      break;
  }

  close(m_trackerSock);
  FD_CLR(m_trackerSock, &m_readSocks);


  bencoding::Dictionary dict;

  std::stringstream tss;
  tss.str(bodyOs.str());
  dict.wireDecode(tss);

  TrackerResponse trackerResponse;
  trackerResponse.decode(dict);
  m_peers = trackerResponse.getPeers();
  m_interval = trackerResponse.getInterval();

  if (m_isFirstRes) {
    for (const auto& peer : m_peers) {
      std::cout << peer.ip << ":" << peer.port << std::endl;
    }
  }

  m_isFirstRes = false;
}
void* connectPeer(void * args) {
        int code = pthread_detach(pthread_self());
        if (code != 0) {
          std::cout <<"detach thread failed" << std::endl;
          return NULL;
        }
        sbt::peer_args* p_args = (struct peer_args*) args;
        sbt::PeerInfo peer = p_args->peerInfo;
        sbt::Client* client = p_args->client;
	// do not set up connection to client itself
	if (peer.ip == "127.0.0.1" && peer.port == client->m_clientPort)
	    return NULL;
	// do not set up connection with same peer
	if (client->m_connectedPeers.find(peer.peerId) != client->m_connectedPeers.end())
	    return NULL;

	int peerSock = socket(AF_INET, SOCK_STREAM, 0);

	struct addrinfo hints;
	struct addrinfo* res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int status = 0;
	if ((status = getaddrinfo(peer.ip.c_str(), std::to_string(peer.port).c_str(), &hints, &res)) != 0)
		std::cout << "Cannot resolve peer ip" << std::endl;

	struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
	char ipstr[INET_ADDRSTRLEN] = {'\0'};
	inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));

	std::cout <<"trying to connect" << std::endl;
	if (connect(peerSock, res->ai_addr, res->ai_addrlen) == -1) {
		perror("connect");
		return NULL;
	}

	// if successfully connected, add to connected peers set
	client->m_connectedPeers.insert(make_pair(peer.peerId, peerSock));
	client->handshake(peer.peerId, peerSock);
        client->m_connectedPeers.erase(peer.peerId);
        close(peerSock);
	freeaddrinfo(res);
        std::cout << "done" <<std::endl;
	return NULL;	
}

void Client::handshake(std::string peerId, int sock) {

    msg::HandShake hs(m_metaInfo.getHash(), peerId);
    int res = send(sock, reinterpret_cast<const char *>(hs.encode()->buf()), 68, 0);
    if ( res == -1) {
      perror("handshake send");
      return;
    }
    char* buf = (char *) malloc(68);

    res = -1;
    
    res = recv(sock, buf, 68, 0);
    if (res == -1) {
      perror("handshake receive");
    }

    msg::HandShake received_hs;
    sbt::OBufferStream buf_stream;
    buf_stream.write(buf, 68);
    BufferPtr buf_ptr = buf_stream.buf();
    received_hs.decode(buf_ptr);
    std::cout << "got handshake" << std::endl;
    //free(buf);
    bitfield(sock);


}

void Client::bitfield(int sock) {
  sbt::OBufferStream buf_stream;
  buf_stream.write(m_bitfield, m_bitfield_size);
  BufferPtr buf_ptr = buf_stream.buf();

  msg::Bitfield bf(buf_ptr); 

  int res = send(sock, reinterpret_cast<const char *>(bf.encode()->buf()), 5+m_bitfield_size, 0); 
  if (res == -1) {
    perror("bitfield send");
    return;
  }
  std::cout << "bitfield sent" << std::endl;
  char * received_buf = (char *) malloc(m_bitfield_size+5);
  res = recv(sock, received_buf, 5+m_bitfield_size, 0);
  if (res == -1) {
    perror("bitfield receive");
    return;
  }

  std::cout << "bitfield received: " << std::endl; //<< std::hex << (int) received_buf[5] << std::hex << (int)received_buf[6] << std::hex << (int) received_buf[7] << std::endl;
  // send requests for missing pieces
  bool found = false;
  for (int i = 0; i < m_bitfield_size; i++) {
    // figure out missing pieces
    for (int j = 7; j >= 0; j--) {
      if (!((m_bitfield[i] >> j) & 0x01) && ((received_buf[i + 5] >> j) & 0x01)){
        int index = (i * 8) + (7 - j); 
        interested(sock, index);
        found = true;
        break;
      }
    }
    if(found)
      break;
  }
  //free(received_buf);
  return;
}

void Client::interested(int sock, int index) {

  msg::Interested interested_msg; 

  int res = send(sock, reinterpret_cast<const char *>(interested_msg.encode()->buf()), 5, 0); 
  if (res == -1) {
    perror("interested send");
    return;
  }

  std::cout << "interested sent: " << index << std::endl;

  char * received_buf = (char *) malloc(5);
  res = recv(sock, received_buf, 5, 0);
  if (res == -1) {
    perror("unchoke receive");
    return;
  }
  std::cout << "got unchoke" << std::endl;
  if (received_buf[4] == 1) {
    request(sock, index);
  }
  //free(received_buf);
}

void Client::request(int sock, int index) {
  uint64_t piece_length = m_metaInfo.getPieceLength();
  //if (index == m_num_bits-1) 
  //  piece_length = m_metaInfo.getLength() % piece_length;
  msg::Request request_msg(index, 0, (uint32_t) m_metaInfo.getPieceLength());
  int res = send(sock, reinterpret_cast<const char *>(request_msg.encode()->buf()), 17, 0);
  if (res == -1) {
    perror("request piece send");
    return;
  }

  std::cout << "request sent:" << index << std::endl;

  char * received_buf = (char *) malloc(piece_length+13);
  
  unsigned int curr_length = 0;
  char* piece_buf;
  if (index == m_num_bits-1) {
    piece_buf = (char *)malloc(m_metaInfo.getLength() % m_metaInfo.getPieceLength());
  } else {
    piece_buf = (char *)malloc(piece_length);
  }
  while (curr_length < piece_length) {
    res = recv(sock, received_buf, piece_length+13, 0);
    if (res == -1) {
      perror("piece recieve");
      return;
    }
    if (received_buf[4] == 7) {
        std::cout <<"hello1" << std::endl;
      int msg_length = getMessageLength(received_buf);
      std::cout <<"piece_length" << msg_length <<std::endl;
      if (index == m_num_bits-1) {
        memcpy(piece_buf+curr_length, received_buf+13, m_metaInfo.getLength() % m_metaInfo.getPieceLength());
      } else {
  std::cout <<"hello:"<<msg_length << std::endl;
        memcpy(piece_buf+curr_length, received_buf+13, msg_length-9);
      }
      std::cout << "got piece" << std::endl;
      curr_length += (msg_length - 9);
      memset(received_buf, 0, piece_length+13);
    } else {
      std::cout << "request receive broke" << std::endl;
      break;
    }
  }

    std::cout << "got whole piece" << std::endl;
    std::string piece_buf_string(piece_buf);
    std::string piece_hash_string = util::sha1(piece_buf_string);

    char known_piece_hash[20];
    std::vector<uint8_t> all_piece_hash = m_metaInfo.getPieces();

    for (int i = 0; i < 20; i++) {
      known_piece_hash[i] = (char)(all_piece_hash[i+20*index]);
    }


    //CRITICAL SECTION PLS
    if(memcmp(piece_hash_string.c_str(), known_piece_hash, 20) == 0) {
      std::cout << "hashes match" << std::endl;
      //write to file
      memcpy(m_file_byte_array + (index*m_metaInfo.getPieceLength()), piece_buf, piece_length);
      m_amount_downloaded += piece_length;
      m_bitfield[index/8] |= (0x1 << (7 - (index % 8)));
    std::cout << "downloaded:" << m_amount_downloaded << std::endl;
   
      have(index, sock);
      //free(received_buf);
      //free(piece_buf);
    } else {
      std::cout << "don't match" << std::endl;
      //free(received_buf);
      //free(piece_buf);	
      request(sock, index);
      return;
    }
   
}

void Client::have(int index, int sock) {
   msg::Have have_msg(index);
int res = send(sock, reinterpret_cast<const char *>(have_msg.encode()->buf()), 9, 0);

/*  for (auto it = m_connectedPeers.begin(); it != m_connectedPeers.end(); it++) {
    if (res == -1) {
      perror("have send");
      return;
    }
  }*/
  std::cout << "send haves" << std::endl;
}

int Client::getMessageLength(char* buf) {
  return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
}
} // namespace sbt
