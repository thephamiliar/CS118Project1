#include "client.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include "meta-info.hpp"
#include "http/http-request.hpp"
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
  serverAddr.sin_port = htons(40000);
  serverAddr.sin_addr.s_addr = inet_addr("172.31.30.204");
  memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

  if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
    perror("connect");
    return 2;
  }
  std::cout << "helllll yeee";
  return 0;
}

void Client::getTrackerInfo() {
    
} 

HttpRequest Client::makeHttpRequest() {
    HttpRequest req;
//    req.setMethod(GET);
    // host
/*    string metaInfo.getAnnounce();
    
    req.setHost();
    // port
    req.setPort();
    // path
    req.setPath();
    // version
    req.setVersion("1.0");
*/
    // create buffer with GetTotalLength() size
    // req.formatRequest();
    return req;
}

void Client::sendTrackerRequest() {
    
}

} // namespace sbt
