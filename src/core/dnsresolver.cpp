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

#include "dnsresolver.h"
#include <algorithm>
#include <boost/asio/error.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/system_error.hpp>
#include <cctype>
#include <map>
#include <thread>
#include <utility>

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

namespace
{
string normalize_host(const string& host)
{
    string normalized(host);
    transform(normalized.begin(),
              normalized.end(),
              normalized.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return normalized;
}

void system_resolve(const string& host, boost::system::error_code& ec, DNSResolver::AddressResults& addresses)
{
    io_context io_context;
    tcp::resolver resolver(io_context);
    auto results = resolver.resolve(host, "0", ec);
    if (ec)
    {
        return;
    }
    for (const auto& result : results)
    {
        const auto address = result.endpoint().address();
        if (find(addresses.begin(), addresses.end(), address) == addresses.end())
        {
            addresses.emplace_back(address);
        }
    }
    if (addresses.empty())
    {
        ec = boost::asio::error::host_not_found;
    }
}
}  // namespace

DNSResolver::Options::Options()
    : threads(4),
      timeout(std::chrono::seconds(5)),
      cache_timeout(std::chrono::seconds(60)),
      negative_cache_timeout(std::chrono::seconds(30)),
      max_pending(64)
{
}

DNSResolver::Request::State::State() : cancelled(false) {}

DNSResolver::Request::Request() = default;

DNSResolver::Request::Request(const shared_ptr<State>& state) : state(state) {}

void DNSResolver::Request::cancel()
{
    if (state)
    {
        state->cancelled.store(true);
    }
}

struct DNSResolver::Impl : public enable_shared_from_this<DNSResolver::Impl>
{
    struct Waiter
    {
        shared_ptr<Request::State> state;
        AddressHandler handler;
    };

    struct Job
    {
        Job(io_context& io_context, string host, string key, uint64_t id)
            : host(std::move(host)), key(std::move(key)), id(id), timer(io_context), expired(false)
        {
        }

        string host;
        string key;
        uint64_t id;
        steady_timer timer;
        atomic<bool> expired;
        vector<Waiter> waiters;
    };

    struct CacheEntry
    {
        boost::system::error_code error;
        AddressResults addresses;
        std::chrono::steady_clock::time_point expires_at;
    };

    Impl(io_context& callback_io, Options options, ResolveFunction resolve_function)
        : callback_io(callback_io),
          worker_work(new WorkGuard(worker_io.get_executor())),
          options(std::move(options)),
          resolve_function(resolve_function ? std::move(resolve_function) : ResolveFunction(system_resolve)),
          outstanding_jobs(0),
          next_id(1),
          stopping(false)
    {
        this->options.threads     = max<size_t>(1, min<size_t>(this->options.threads, 32));
        this->options.max_pending = max<size_t>(this->options.threads, min<size_t>(this->options.max_pending, 4096));
        if (this->options.timeout <= std::chrono::milliseconds::zero())
        {
            this->options.timeout = std::chrono::seconds(5);
        }
        if (this->options.cache_timeout < std::chrono::milliseconds::zero())
        {
            this->options.cache_timeout = std::chrono::milliseconds::zero();
        }
        if (this->options.negative_cache_timeout < std::chrono::milliseconds::zero())
        {
            this->options.negative_cache_timeout = std::chrono::milliseconds::zero();
        }
    }

    ~Impl() { shutdown(); }

    void start()
    {
        for (size_t i = 0; i < options.threads; ++i)
        {
            workers.emplace_back([this]() { worker_io.run(); });
        }
    }

    void shutdown()
    {
        if (stopping)
        {
            return;
        }
        stopping = true;
        for (auto& item : in_flight)
        {
            item.second->expired.store(true);
            boost::system::error_code ec;
            item.second->timer.cancel(ec);
            for (auto& waiter : item.second->waiters)
            {
                waiter.state->cancelled.store(true);
            }
        }
        in_flight.clear();
        timed_out_jobs.clear();
        cache.clear();
        worker_work.reset();
        worker_io.stop();
        for (auto& worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
        workers.clear();
    }

    Request resolve(const string& host, AddressHandler handler)
    {
        auto state = make_shared<Request::State>();
        if (stopping)
        {
            state->cancelled.store(true);
            return Request(state);
        }

        boost::system::error_code address_error;
        auto numeric_address = make_address(host, address_error);
        if (!address_error)
        {
            post_result(state, std::move(handler), boost::system::error_code(), AddressResults {numeric_address});
            return Request(state);
        }

        const string key = normalize_host(host);
        const auto now   = std::chrono::steady_clock::now();
        auto cache_item  = cache.find(key);
        if (cache_item != cache.end())
        {
            if (cache_item->second.expires_at > now)
            {
                post_result(state, std::move(handler), cache_item->second.error, cache_item->second.addresses);
                return Request(state);
            }
            cache.erase(cache_item);
        }

        auto active = in_flight.find(key);
        if (active != in_flight.end())
        {
            if (active->second->waiters.size() >= 256)
            {
                post_result(state, std::move(handler), boost::asio::error::no_buffer_space, AddressResults());
                return Request(state);
            }
            active->second->waiters.push_back(Waiter {state, std::move(handler)});
            return Request(state);
        }

        if (timed_out_jobs.find(key) != timed_out_jobs.end())
        {
            // The caller has already timed out, but getaddrinfo() cannot be
            // interrupted portably. Do not start another lookup for this host
            // until the original operating-system call returns.
            post_result(state, std::move(handler), boost::asio::error::timed_out, AddressResults());
            return Request(state);
        }

        if (outstanding_jobs >= options.max_pending)
        {
            post_result(state, std::move(handler), boost::asio::error::no_buffer_space, AddressResults());
            return Request(state);
        }

        auto job = make_shared<Job>(callback_io, host, key, next_id++);
        job->waiters.push_back(Waiter {state, std::move(handler)});
        in_flight.emplace(key, job);
        ++outstanding_jobs;

        weak_ptr<Impl> weak_impl(shared_from_this());
        job->timer.expires_after(options.timeout);
        job->timer.async_wait(
            [weak_impl, job](const boost::system::error_code& error)
            {
                if (error)
                {
                    return;
                }
                auto impl = weak_impl.lock();
                if (impl)
                {
                    impl->timeout_job(job);
                }
            });

        const ResolveFunction worker_resolve = resolve_function;
        worker_io.post(
            [weak_impl, job, worker_resolve]()
            {
                boost::system::error_code error = boost::asio::error::operation_aborted;
                AddressResults addresses;
                if (!job->expired.load())
                {
                    error.clear();
                    try
                    {
                        worker_resolve(job->host, error, addresses);
                    }
                    catch (const boost::system::system_error& exception)
                    {
                        error = exception.code();
                    }
                    catch (...)
                    {
                        error = boost::asio::error::fault;
                    }
                }
                auto impl = weak_impl.lock();
                if (impl)
                {
                    impl->callback_io.post(
                        [weak_impl, job, error, addresses]()
                        {
                            auto active_impl = weak_impl.lock();
                            if (active_impl)
                            {
                                active_impl->complete_job(job, error, addresses);
                            }
                        });
                }
            });
        return Request(state);
    }

    void timeout_job(const shared_ptr<Job>& job)
    {
        auto active = in_flight.find(job->key);
        if (active == in_flight.end() || active->second->id != job->id)
        {
            return;
        }
        job->expired.store(true);
        vector<Waiter> waiters;
        waiters.swap(job->waiters);
        in_flight.erase(active);
        timed_out_jobs[job->key] = job->id;
        store_cache(job->key, boost::asio::error::timed_out, AddressResults(), options.negative_cache_timeout);
        deliver(waiters, boost::asio::error::timed_out, AddressResults());
    }

    void
    complete_job(const shared_ptr<Job>& job, const boost::system::error_code& error, const AddressResults& addresses)
    {
        if (outstanding_jobs > 0)
        {
            --outstanding_jobs;
        }
        auto active = in_flight.find(job->key);
        if (active == in_flight.end() || active->second->id != job->id)
        {
            auto timed_out = timed_out_jobs.find(job->key);
            if (timed_out != timed_out_jobs.end() && timed_out->second == job->id)
            {
                timed_out_jobs.erase(timed_out);
            }
            return;
        }

        boost::system::error_code timer_error;
        job->timer.cancel(timer_error);
        vector<Waiter> waiters;
        waiters.swap(job->waiters);
        in_flight.erase(active);

        const auto cache_duration = error ? options.negative_cache_timeout : options.cache_timeout;
        store_cache(job->key, error, addresses, cache_duration);
        deliver(waiters, error, addresses);
    }

    void store_cache(const string& key,
                     const boost::system::error_code& error,
                     const AddressResults& addresses,
                     std::chrono::milliseconds duration)
    {
        if (duration <= std::chrono::milliseconds::zero())
        {
            return;
        }
        cache[key] = CacheEntry {error, addresses, std::chrono::steady_clock::now() + duration};
    }

    void deliver(vector<Waiter>& waiters, const boost::system::error_code& error, const AddressResults& addresses)
    {
        for (auto& waiter : waiters)
        {
            if (!waiter.state->cancelled.load())
            {
                waiter.handler(error, addresses);
            }
        }
    }

    void post_result(const shared_ptr<Request::State>& state,
                     AddressHandler handler,
                     const boost::system::error_code& error,
                     const AddressResults& addresses)
    {
        callback_io.post(
            [state, handler, error, addresses]()
            {
                if (!state->cancelled.load())
                {
                    handler(error, addresses);
                }
            });
    }

    io_context& callback_io;
    io_context worker_io;
    typedef executor_work_guard<io_context::executor_type> WorkGuard;
    unique_ptr<WorkGuard> worker_work;
    vector<thread> workers;
    Options options;
    ResolveFunction resolve_function;
    map<string, CacheEntry> cache;
    map<string, shared_ptr<Job>> in_flight;
    map<string, uint64_t> timed_out_jobs;
    size_t outstanding_jobs;
    uint64_t next_id;
    bool stopping;
};

DNSResolver::DNSResolver(io_context& io_context, const Options& options, ResolveFunction resolve_function)
    : impl(make_shared<Impl>(io_context, options, std::move(resolve_function)))
{
    impl->start();
}

DNSResolver::~DNSResolver()
{
    if (impl)
    {
        impl->shutdown();
        impl.reset();
    }
}

DNSResolver::Request DNSResolver::async_resolve(const string& host, AddressHandler handler)
{
    return impl->resolve(host, std::move(handler));
}

DNSResolver::Request DNSResolver::async_resolve_tcp(const string& host, uint16_t port, TCPHandler handler)
{
    return async_resolve(host,
                         [port, handler](const boost::system::error_code& error, const AddressResults& addresses)
                         {
                             TCPResults endpoints;
                             if (!error)
                             {
                                 for (const auto& address : addresses)
                                 {
                                     endpoints.emplace_back(address, port);
                                 }
                             }
                             handler(error, endpoints);
                         });
}

DNSResolver::Request DNSResolver::async_resolve_udp(const string& host, uint16_t port, UDPHandler handler)
{
    return async_resolve(host,
                         [port, handler](const boost::system::error_code& error, const AddressResults& addresses)
                         {
                             UDPResults endpoints;
                             if (!error)
                             {
                                 for (const auto& address : addresses)
                                 {
                                     endpoints.emplace_back(address, port);
                                 }
                             }
                             handler(error, endpoints);
                         });
}
