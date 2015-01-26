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
#include <sstream>
#include "meta-info.hpp"
#include "http/http-request.hpp"
#include "http/url-encoding.hpp"
#include "util/bencoding.hpp"
#include "tracker-response.hpp"
using std::string;

namespace sbt {

MetaInfo Client::getMetaInfo() {
    return metaInfo;
}

int Client::connectToServer(std::string portNum) {
  HttpRequest req = makeHttpRequest(true);
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(getTrackerPortNumber());
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
  //std::cout << serverAddr.sin_port << " " << serverAddr.sin_addr.s_addr;
  if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
    perror("connect");
    return 2;
  }
  
  char* buf = new char[req.getTotalLength()];

  req.formatRequest(buf);
  if (send(sockfd, buf, req.getTotalLength(), 0) == -1) {
    perror("send");
  }

  char* recv_buf = new char[10000];
  memset(recv_buf, '\0', 10000);
  int ret_val = recv(sockfd, recv_buf, 10000, 0);
  if (ret_val == -1) {
    perror("pineapple");
  }
  int recv_buf_size = 0;
  for(;recv_buf[recv_buf_size] != '\0'; recv_buf_size++);

  //std::cout << recv_buf << std::endl;
  const char* start_body = trackerRes.parseResponse(recv_buf, recv_buf_size);
  //int body_length = stoi(trackerRes.findHeader("Content-Length"));
  std::istringstream str(start_body);
  bencoding::Dictionary body;
  body.wireDecode(str);
  
  TrackerResponse tracker_info;
  tracker_info.decode(body);

  peer_list = tracker_info.getPeers();
  interval = tracker_info.getInterval();

  for (auto it = peer_list.begin(); it != peer_list.end(); it++) {
      std::cout << it->ip << ":" << it->port << std::endl;
  }
  close(sockfd);
  
  while(true) {
    sleep(interval);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      perror("connect");
      return 2;
    }
    HttpRequest new_req = makeHttpRequest(false);
    char *new_buf = new char[new_req.getTotalLength()];
    memset(new_buf, '\0', new_req.getTotalLength());
    new_req.formatRequest(new_buf);


    if (send(sockfd, new_buf, new_req.getTotalLength(), 0) == -1) {
      perror("send");
    }

    int ret_val = recv(sockfd, recv_buf, 10000, 0);
    if (ret_val == -1) {
      perror("pineapple");
    }
   
    recv_buf_size = 0;
    for(;recv_buf[recv_buf_size] != '\0'; recv_buf_size++);

    //std::cout << recv_buf << std::endl;
    start_body = trackerRes.parseResponse(recv_buf, recv_buf_size);
    //int body_length = stoi(trackerRes.findHeader("Content-Length"));
    std::istringstream str(start_body);
    body.wireDecode(str);
  
    tracker_info.decode(body);

    interval = tracker_info.getInterval();

    free(new_buf);
    close(sockfd);
    
  }
  return 0;
} 

HttpRequest Client::makeHttpRequest(bool includeEvent) {
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
    const char* pstr = getServerPortNumber().c_str();
    trackerPortNumber = (unsigned short) strtoul(port.c_str(), NULL, 0);
    // path: uri, hash, ip, port, event
    req.setPort(trackerPortNumber);
    string info_hash = url::encode(metaInfo.getHash()->get(), metaInfo.getHash()->size());
    string ip = "127.0.0.1";
    string uploaded = "0";
    string downloaded = "0";
    string left = "0";
    string fullPath = path + "?info_hash=" + info_hash + "&ip="+ ip + "&port=" + pstr + "&uploaded=" + uploaded + "&downloaded=" + downloaded + "&left=" + left; 
    if (includeEvent) {
      fullPath += "&event=started";
    }
    req.setPath(fullPath);
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
