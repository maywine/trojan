#pragma once

#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <unordered_map>
#include <boost/functional/hash.hpp>
#include <boost/algorithm/string.hpp>

std::string make_request(const std::string &request_type,
                         const std::string &host,
                         const std::string &path = "/",
                         const std::string *request = nullptr,
                         const std::map<std::string, std::string> &header = std::map<std::string, std::string>());

std::string make_respone(const std::string &status_code,
                         const std::string *respone = nullptr,
                         const std::map<std::string, std::string> &header = std::map<std::string, std::string>());

struct CaseInsensitiveEquals
{
    bool operator()(const std::string &key1, const std::string &key2) const
    {
        return boost::algorithm::iequals(key1, key2);
    }
};

struct CaseInsensitiveHash
{
    std::size_t operator()(const std::string &key) const
    {
        std::size_t seed = 0;
        for (const auto &c : key)
        {
            boost::hash_combine(seed, std::tolower(c));
        }
        return seed;
    }
};

class HttpRequestParse
{
public:
    struct HttpRequset
    {
        std::string method;
        std::string path;
        std::string http_version;
        std::string requset_body;
        std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEquals> headers;

        std::string peer_endpoint_addr;
        uint16_t peer_endpoint_port = 0;

        void Clear()
        {
            method.clear();
            path.clear();
            http_version.clear();
            requset_body.clear();
            headers.clear();
            peer_endpoint_addr.clear();
            peer_endpoint_port = 0;
        }
    };

    HttpRequestParse()
    {
        buf_vec_.resize(1024);
    }
    ~HttpRequestParse() = default;

    bool ParseHttpRequset(const char *data, const uint32_t data_len)
    {
        if (data_len == 0)
        {
            return true;
        }

        if (data_len > (buf_vec_.size() - end_))
        {
            auto len = end_ - beg_;
            std::copy(Pos(beg_), Pos(end_), Pos(0));
            beg_ = 0;
            end_ = len;
            if (data_len > (buf_vec_.size() - end_))
            {
                std::size_t resize = buf_vec_.size() * 2;
                resize = (resize - end_) < data_len ? (resize + data_len) : resize;
                buf_vec_.resize(resize);
            }
        }

        std::copy(data, data + data_len, Pos(end_));
        end_ += data_len;
        if (!parse_header_done_)
        {
            auto header_end = FindFirstOf("\r\n\r\n");
            if (header_end != end_)
            {
                header_end += 4;
                if (!ParseRequsetHeader(beg_, header_end))
                {
                    return false;
                }
                beg_ = header_end;
            }
        }
        
        if (parse_header_done_ && !parse_done_)
        {
            if (content_length_ < 0)
            {
                return false;
            }

            if (uint64_t(content_length_) <= (end_ - beg_))
            {
                http_requset_.requset_body.reserve(content_length_);
                std::copy(Pos(beg_), Pos(beg_) + content_length_, std::back_inserter(http_requset_.requset_body));
                beg_ += content_length_;
                parse_done_ = true;
            }
        }

        return true;
    }

    void Reset()
    {
        parse_header_done_ = false;
        parse_done_ = false;
        content_length_ = -1;
        beg_ = 0;
        end_ = 0;
        http_requset_.Clear();
    }

    inline bool parse_done() const
    {
        return parse_done_;
    }

    inline const HttpRequset &http_requset() const
    {
        return http_requset_;
    }

private:
    inline char *Pos(uint64_t pos)
    {
        return &buf_vec_[pos];
    }

    uint64_t FindFirstOf(const std::string &str)
    {
        if (str.empty())
        {
            return end_;
        }

        for (auto pos = beg_; pos < end_; ++pos)
        {
            if (buf_vec_[pos] == str[0] && (end_ - pos) >= str.size())
            {
                bool is_same = true;
                for (std::size_t i = 0; i < str.size(); ++i)
                {
                    if (buf_vec_[pos + i] != str[i])
                    {
                        is_same = false;
                        break;
                    }
                }

                if (is_same)
                {
                    return pos;
                }
            }
        }

        return end_;
    }

    bool ParseRequsetHeader(const uint64_t beg, const uint64_t end)
    {
        std::string line;
        std::stringstream iostr;
        iostr.write(Pos(beg), end - beg);

        std::getline(iostr, line);
        std::size_t method_end = line.find(' ');
        if (method_end == std::string::npos)
        {
            return false;
        }

        std::size_t path_end = line.find(' ', method_end + 1);
        if (path_end == std::string::npos)
        {
            return false;
        }

        std::size_t protocol_end = line.find('/', path_end + 1);
        if (protocol_end == std::string::npos)
        {
            return false;
        }

        if (line.compare(path_end + 1, protocol_end - path_end - 1, "HTTP") != 0)
        {
            return false;
        }

        http_requset_.method = line.substr(0, method_end);
        http_requset_.path = line.substr(method_end + 1, path_end - method_end - 1);
        http_requset_.http_version = line.substr(protocol_end + 1, line.size() - protocol_end - 2);

        std::size_t param_end;
        std::getline(iostr, line);
        while ((param_end = line.find(':')) != std::string::npos)
        {
            std::size_t value_start = param_end + 1;
            if (value_start < line.size())
            {
                if (line[value_start] == ' ')
                {
                    ++value_start;
                }

                if (value_start < line.size())
                {
                    auto key = line.substr(0, param_end);
                    auto value = line.substr(value_start, line.size() - value_start - 1);
                    if (key == "Content-Length")
                    {
                        try
                        {
                            content_length_ = std::stoll(value);
                        }
                        catch (...)
                        {
                            return false;
                        }
                    }
                    http_requset_.headers.emplace(std::move(key), std::move(value));
                }
            }
            std::getline(iostr, line);
        }

        parse_header_done_ = true;
        return true;
    }

    bool parse_header_done_ = false;
    bool parse_done_ = false;
    int64_t content_length_ = -1;
    uint64_t beg_ = 0;
    uint64_t end_ = 0;
    std::vector<char> buf_vec_;
    HttpRequset http_requset_;
};
