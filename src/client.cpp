#include "client.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include "meta-info.hpp"
#include "http/http-request.hpp"
#include "http/url-encoding.hpp"
using std::string;

namespace sbt {

string Client::getPortNumber() {
    return portNumber;
}

MetaInfo Client::getMetaInfo() {
    return metaInfo;
}

int Client::connectToServer(std::string portNum) {

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(std::stoi(portNum));
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
  //std::cout << serverAddr.sin_port << " " << serverAddr.sin_addr.s_addr;
  if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
    perror("connect");
    return 2;
  }
  
  HttpRequest req = makeHttpRequest();
  char* buf = new char[req.getTotalLength()];

  req.formatRequest(buf);
  if (send(sockfd, buf, req.getTotalLength(), 0) == -1) {
    perror("send took a shit");
  }

  memset(buf, '\0', sizeof(buf));

  if (recv(sockfd, buf, sizeof(buf), 0) == -1) {
    perror("pineapple");
  }
  std::cout << buf << std::endl;
  return 0;
}

void Client::getTrackerInfo() {
    
} 

HttpRequest Client::makeHttpRequest() {
    HttpRequest req;
    req.setMethod(HttpRequest::GET);
    string announce = metaInfo.getAnnounce();
    string path;
    string host;
    int found = 0;
    for (unsigned int i = 0; i < announce.size(); i++) {
      if (announce[i] == '/') {
        found++;
      }
      if (found == 3) {
        path = announce.substr(i, announce.size() - i);
        host = announce.substr(0, i);
        break;
      }
    }
    
    string port;
    found = 0;
    for (unsigned int i = 0; i < host.size(); i++) {
      if (host[i] == ':') {
        found++;
      }
      if (found == 2) {
        port = host.substr(i+1, host.size() - i);
        host = host.substr(0, i);
        break;
      }
    }
    req.setHost(host);
    // port
    const char* pstr = port.c_str();
    req.setPort((unsigned short) strtoul(pstr, NULL, 0));
    // path: uri, hash, ip, port, event
    string info_hash = url::encode(metaInfo.getHash()->get(), metaInfo.getHash()->size());
    string ip = "127.0.0.1";
    string event = "started";
    string fullPath = path + "?info_hash=" + info_hash + "&ip="+ ip + "&port=" + portNumber + "&event=" + event; 

    req.setPath(path);
    // version
    req.setVersion("1.0");
    req.addHeader("Accept-Language", "en-US");
    // create buffer with GetTotalLength() size
    // req.formatRequest();
    return req;
}

void Client::sendTrackerRequest() {
    
}

} // namespace sbt
