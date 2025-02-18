#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <algorithm>
#include <memory>
#include <fstream>
#include <thread>

#include <getopt.h>

#include "tc_eventloop.h"

EventLoop g_loop;

namespace {
std::string readFileToString(const char* path) {
    // 创建输入文件流
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file) {
        return "";
    }

    // 使用 stringstream 将文件内容读入 string
    std::ostringstream contents;
    contents << file.rdbuf();  // 读取文件的整个缓冲区
    file.close();

    return contents.str();  // 返回文件内容
}

void print_usage() {
  std::cerr << "Usage: client [OPTIONS] [<URI>...]" << std::endl;
  std::cerr << R"(
  <URI>       Remote URI)" << std::endl;
}
int parse_uri(taf::TC_HttpRequest &req, const string &url,
              const string &http_method,
              const std::vector<std::pair<std::string, std::string>> &headers,
              const string &data) {
    if (http_method == "POST") {
        req.setPostRequest(url, data);
    }
    if (http_method == "GET") {
        req.setGetRequest(url);
    }
    for (const auto &[name, value] : headers) {
        req.setHeader(name, value);
    }
    return 0;
}

int parse_requests(int argc, char **argv,
                   vector<shared_ptr<taf::TC_HttpRequest>> &requests) {
    string data;
    string http_method = "GET";
    std::vector<std::pair<std::string, std::string>> headers;

    for (;;) {
        if (argc < 2) {
            std::cerr << "Too few arguments" << std::endl;
            print_usage();
            exit(EXIT_FAILURE);
        }
        static int flag = 0;
        constexpr static option long_opts[] = {
            {"data", required_argument, nullptr, 'd'},
            {"http-method", required_argument, nullptr, 'm'},
            {"header", required_argument, &flag, 1},
            {nullptr, 0, nullptr, 0},
        };

        auto optidx = 0;
        auto c = getopt_long(argc, argv, "d:m:", long_opts, &optidx);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'd': {
                // --data
                char *data_path = optarg;
                data = readFileToString(data_path);
                break;
            }
            case 'm':
                // --http-method
                http_method = optarg;
                break;
            case 0:
                switch (flag) {
                    case 1: {
                        // 添加用户指定的请求头
                        std::string header_line = optarg;
                        auto colon_pos = header_line.find(':');
                        if (colon_pos == std::string::npos) {
                            std::cerr
                                << "Invalid header format: " << header_line
                                << std::endl;
                            return -1;
                        }
                        auto name = header_line.substr(0, colon_pos);
                        auto value = header_line.substr(colon_pos + 1);
                        // 去除可能的空格
                        while (!value.empty() &&
                               (value[0] == ' ' || value[0] == '\t')) {
                            value.erase(0, 1);
                        }
                        // 将名称转换为小写
                        std::transform(
                            name.begin(), name.end(), name.begin(),
                            [](unsigned char c) { return std::tolower(c); });
                        headers.push_back({name, value});
                        break;
                    }
                    default:
                        break;
                }
            default:
                break;
        }
    }
    for (size_t i = optind; i < argc; ++i) {
        auto uri = argv[i];
        cout << uri << endl;
        taf::TC_HttpRequest req;
        if (parse_uri(req, uri, http_method, headers, data) != 0) {
            std::cerr << "Could not parse URI: " << uri << std::endl;
            return -1;
        }
        requests.emplace_back(make_shared<taf::TC_HttpRequest>(std::move(req)));
    }
    return 0;
}
} // namespace

int main(int argc, char **argv) {
  std::vector<shared_ptr<taf::TC_HttpRequest>> requests;

  if (parse_requests(argc, argv, requests) != 0) {
    exit(EXIT_FAILURE);
  }

  Http3Conn::initConfig();

  std::thread t([] {
    g_loop.run();
  });

  for (auto &req : requests) {
    g_loop.doRequest(req);
  }

  sleep(2);

  for (auto &req : requests) {
    g_loop.doRequest(req);
  }

  t.join();

  return EXIT_SUCCESS;
}