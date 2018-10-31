Simple DoH Server
=================

Minimal DNS over HTTPS server.  Proxies HTTPS (or HTTP or FastCGI) requests for
DNS queries.

Not really tested yet.  Please don't use it for anything which matters.

For legal use only.

Quickstart
----------
```bash
go install github.com/magisterquis/simpledohserver
simpledohserver -h #See the available options
# Forward external port 443 to 127.0.0.1:4433
simpledohserver -cert /path/to/tls/cert.pem -key /path/to/tls/key.pem
```

Nifty Features
--------------
- Content-type settable by the requestor
- Pretty-printed returned JSON
- FastCGI listener for use with webservers (e.g. Nginx, Apache)
- Plaintext HTTP listener
- Logging of every query
- Cryptic errors sent to clients

Not supported
-------------
The following are features common to DoH servers but which aren't supported.

- Configurable upstream DNS server(s)
- Query types other than A, NS, PTR, MX, TXT, AAAA, and SRV
- DNSSEC
- TTLs from upstream servers

Pull requests are welcome.

Hang on, why would I use such a thing?
--------------------------------------
Well, you probably have no need to.  For most people using DNS over HTTPS,
using one of the publicly-accessible servers is probably sufficient.  This, on
the other hand, is really handy for testing tools which use DoH without sharing
queries during development with organizations running DoH servers.  It's
probably reasonably easy to use for a personal DoH server to compliment other
measures meant to ensure privacy.

Usage
-----
The usage statement (i.e. what you get with `-h`) is below:

```
Usage: simpledohserver [options]

Serves DNS over HTTPS queries.

Queries should be of the form /resolve?name=something.com&type=T[&content-type=type/type][&pp=]

The query parameters are as follows:
name:         The name for which to do a DNS query
type:         The resource record type to return
content-type: A custom Content-Type to use in the reply
pp:           Causes the response to be pretty-printed (i.e. indented)

Only queries of type A, NS, PTR, MX, TXT, AAAA, and SRV are supported

Options:
  -cert file
    	TLS certificate file (default "cert.pem")
  -content-type MIME type
    	The default MIME type to send in responses (default "application/json")
  -endpoint path
    	REST endpoint path to serve (default "/resolve")
  -fcgi address
    	FastCGI listen address, which may either be a path or an ip:port, or "no" to disable (default "no")
  -http address
    	HTTP listen address or "no" to disable (default "no")
  -https address
    	HTTPS listen address, or "no" to disable (default "127.0.0.1:4433")
  -key file
    	TLS key file (default "key.pem")
  -remove-fcgi-socket
    	Remove an existing FCGI socket before listening
  -ttl seconds
    	TTL to return to clients, in seconds (default 1800)
  -v	Enable verbose logging
```

Errors
------
In order to prevent malicious clients (i.e. pesky blue teams) from learning
anything useful about the server no real error messages are returned.  Instead
an error code is sent back which may be correlated with server logs to learn
more.

For an error returned to a client such as
```
Error number 0fd33510d2a9b7ac
```
a corresponding log entry such as
```
2018/10/30 22:46:32 [127.0.0.1:48632] 400 GET localhost:8080 /resolve?foo=bar No name provided (error number 3fe561f004ef07d7)
```
will be created if the `-v` flag is given.

FastCGI
-------
Aside from HTTPS (and HTTP), DoH can be served over FastCGI to enable use with
servers such as Nginx and Apache.  In this case, it's probably not a bad idea
to disable HTTPS service (`-https no`).

FCGI can be served over either a Unix socket or TCP socket.  In the case of the
former, an existing socket can be removed with `-remove-fcgi-sock`.

Upstream Resolver
-----------------
The resolver used is whatever the Go standard library uses for its `net.Lookup`
functions.  Generally this means whatever libc uses or whatever's in
`/etc/resolv.conf`.  For finer-grained control or to set custom DNS records,
somethnig like [rebound(8)](https://man.openbsd.org/rebound) or
[unbound](https://unbound.net) can be used as the upstream resolver, usually by
having it listen on localhost and putting `nameserver 127.0.0.1` in
`/etc/resolv.conf`.

Windows
-------
Should probably work with the exception of using a Unix domain socket for
FastCGI.  Feel free to send a PR. 
