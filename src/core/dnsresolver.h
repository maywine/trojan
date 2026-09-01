/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _DNSRESOLVER_H_
#define _DNSRESOLVER_H_

#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Boost.Asio emulates asynchronous name resolution with one blocking worker
// per io_context on POSIX. This shared resolver uses a bounded worker pool,
// request coalescing, timeouts and caching so one slow hostname cannot block
// every session in the service.
class DNSResolver
{
public:
    typedef std::vector<boost::asio::ip::address> AddressResults;
    typedef std::vector<boost::asio::ip::tcp::endpoint> TCPResults;
    typedef std::vector<boost::asio::ip::udp::endpoint> UDPResults;
    typedef std::function<void(const boost::system::error_code&, const TCPResults&)> TCPHandler;
    typedef std::function<void(const boost::system::error_code&, const UDPResults&)> UDPHandler;
    typedef std::function<void(const std::string&, boost::system::error_code&, AddressResults&)> ResolveFunction;

    struct Options
    {
        std::size_t threads;
        std::chrono::milliseconds timeout;
        std::chrono::milliseconds cache_timeout;
        std::chrono::milliseconds negative_cache_timeout;
        std::size_t max_pending;

        Options();
    };

    class Request
    {
    public:
        struct State
        {
            State();
            std::atomic<bool> cancelled;
        };

        Request();
        explicit Request(const std::shared_ptr<State>& state);
        void cancel();

    private:
        std::shared_ptr<State> state;
    };

    DNSResolver(boost::asio::io_context& io_context,
                const Options& options           = Options(),
                ResolveFunction resolve_function = ResolveFunction());
    DNSResolver(const DNSResolver&)            = delete;
    DNSResolver& operator=(const DNSResolver&) = delete;
    ~DNSResolver();

    Request async_resolve_tcp(const std::string& host, uint16_t port, TCPHandler handler);
    Request async_resolve_udp(const std::string& host, uint16_t port, UDPHandler handler);

private:
    typedef std::function<void(const boost::system::error_code&, const AddressResults&)> AddressHandler;
    struct Impl;
    std::shared_ptr<Impl> impl;

    Request async_resolve(const std::string& host, AddressHandler handler);
};

#endif  // _DNSRESOLVER_H_
