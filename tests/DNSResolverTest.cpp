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

#include "core/dnsresolver.h"
#include <atomic>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

int main()
{
    io_context io_context;
    DNSResolver::Options options;
    options.threads                = 2;
    options.timeout                = std::chrono::milliseconds(50);
    options.cache_timeout          = std::chrono::seconds(1);
    options.negative_cache_timeout = std::chrono::milliseconds(20);
    options.max_pending            = 8;

    atomic<int> slow_calls(0);
    atomic<int> fast_calls(0);
    DNSResolver resolver(io_context,
                         options,
                         [&slow_calls, &fast_calls](const string& host,
                                                    boost::system::error_code& error,
                                                    DNSResolver::AddressResults& addresses)
                         {
                             if (host == "slow.invalid")
                             {
                                 ++slow_calls;
                                 this_thread::sleep_for(std::chrono::milliseconds(200));
                                 error = boost::asio::error::host_not_found_try_again;
                                 return;
                             }
                             ++fast_calls;
                             addresses.emplace_back(make_address("127.0.0.1"));
                         });

    int slow_timeouts       = 0;
    int cached_slow_timeout = 0;
    int fast_successes      = 0;
    int cached_fast_success = 0;
    bool correct_port       = true;
    vector<DNSResolver::Request> requests;

    for (int i = 0; i < 3; ++i)
    {
        requests.emplace_back(resolver.async_resolve_tcp(
            "slow.invalid",
            80,
            [&resolver, &requests, &slow_timeouts, &cached_slow_timeout](const boost::system::error_code& error,
                                                                         const DNSResolver::TCPResults&)
            {
                if (error == boost::asio::error::timed_out)
                {
                    ++slow_timeouts;
                    if (slow_timeouts == 3)
                    {
                        requests.emplace_back(resolver.async_resolve_tcp(
                            "slow.invalid",
                            80,
                            [&cached_slow_timeout](const boost::system::error_code& cached_error,
                                                   const DNSResolver::TCPResults&)
                            {
                                if (cached_error == boost::asio::error::timed_out)
                                {
                                    ++cached_slow_timeout;
                                }
                            }));
                    }
                }
            }));
    }

    requests.emplace_back(resolver.async_resolve_tcp(
        "fast.test",
        443,
        [&resolver, &requests, &fast_successes, &cached_fast_success, &correct_port](
            const boost::system::error_code& error, const DNSResolver::TCPResults& results)
        {
            if (!error && !results.empty())
            {
                ++fast_successes;
                correct_port = correct_port && results.front().port() == 443;
            }
            requests.emplace_back(resolver.async_resolve_tcp(
                "FAST.TEST",
                8443,
                [&cached_fast_success, &correct_port](const boost::system::error_code& cached_error,
                                                      const DNSResolver::TCPResults& cached_results)
                {
                    if (!cached_error && !cached_results.empty())
                    {
                        ++cached_fast_success;
                        correct_port = correct_port && cached_results.front().port() == 8443;
                    }
                }));
        }));

    steady_timer retry_slow_timer(io_context);
    retry_slow_timer.expires_after(std::chrono::milliseconds(100));
    retry_slow_timer.async_wait(
        [&resolver, &requests, &cached_slow_timeout](const boost::system::error_code& error)
        {
            if (!error)
            {
                requests.emplace_back(
                    resolver.async_resolve_tcp("SLOW.INVALID",
                                               80,
                                               [&cached_slow_timeout](const boost::system::error_code& cached_error,
                                                                      const DNSResolver::TCPResults&)
                                               {
                                                   if (cached_error == boost::asio::error::timed_out)
                                                   {
                                                       ++cached_slow_timeout;
                                                   }
                                               }));
            }
        });

    auto work = make_shared<executor_work_guard<io_context::executor_type>>(io_context.get_executor());
    steady_timer stop_timer(io_context);
    stop_timer.expires_after(std::chrono::milliseconds(300));
    stop_timer.async_wait([&work](const boost::system::error_code&) { work.reset(); });
    io_context.run();

    if (slow_calls.load() != 1 || slow_timeouts != 3 || cached_slow_timeout != 2)
    {
        cerr << "duplicate slow lookups were not coalesced and timed out" << endl;
        return 1;
    }
    if (fast_calls.load() != 1 || fast_successes != 1 || cached_fast_success != 1 || !correct_port)
    {
        cerr << "parallel lookup or positive cache failed" << endl;
        return 1;
    }
    return 0;
}
