#include "http_parse.h"

std::string make_request(const std::string &request_type,
                         const std::string &host,
                         const std::string &path,
                         const std::string *request,
                         const std::map<std::string, std::string> &header)
{
    std::string correct_path = path;
    if (correct_path.empty())
    {
        correct_path = "/";
    }

    std::ostringstream oss;
    oss << request_type << " " << correct_path << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    for (const auto &h : header)
    {
        oss << h.first << ": " << h.second << "\r\n";
    }

    if (request && !request->empty())
    {
        oss << "Content-Length: " << request->size() << "\r\n";
    }
    oss << "\r\n";

    if (request && !request->empty())
    {
        oss << *request;
    }

    return oss.str();
}

std::string make_respone(const std::string &status_code,
                         const std::string *respone,
                         const std::map<std::string, std::string> &header)
{
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status_code << "\r\n";

    if (respone && !respone->empty())
    {
        oss << "Content-Length: " << respone->size() << "\r\n";
    }

    for (const auto &h : header)
    {
        if (h.first != "Content-Length")
        {
            oss << h.first << ": " << h.second << "\r\n";
        }
    }

    oss << "\r\n";

    if (respone && !respone->empty())
    {
        oss << *respone;
    }

    return oss.str();
}
