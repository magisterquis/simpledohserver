// Program simpledohserver implements a simple DNS over HTTPS server
package main

/*
 * simpledohserver.go
 * Simple DNS over HTTPS server
 * By J. Stuart McMurray
 * Created 20181028
 * Last Modified 20181030
 */

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"strings"
)

const (
	// NO is the address which disables a service type
	NO = "no"

	// QNAME is the parameter to specify the name to query
	QNAME = "name"
	// QTYPE is the parameter to specify the RR type
	QTYPE = "type"
	// CTYPE is the parameter to specify a custom content-type header
	CTYPE = "content-type"

	// PRETTY if sent as part of the query will cause the returned JSON
	// to be pretty-printed.
	PRETTY = "pp"
)

// Response is the answer we send back to clients
type Response struct {
	Status   uint
	TC       bool
	RD       bool
	RA       bool
	AD       bool
	CD       bool
	Question []Question
	Answer   []Answer
}

/* answerDatas returns a slice of the Data fields of Answer */
func (r Response) answerData() []string {
	s := make([]string, len(r.Answer))
	for i, a := range r.Answer {
		s[i] = a.Data
	}
	return s
}

// Question contains the question a client sent
type Question struct {
	Name string `json:"name"`
	Type uint   `json:"type"`
}

// Answer contains a resource record
type Answer struct {
	Name string `json:"name"`
	Type uint   `json:"type"`
	TTL  uint
	Data string `json:"data"`
}

// Handler handles DoH queries
type Handler struct {
	ctype    string /* Default content type */
	ttl      uint   /* TTL to return */
	verbose  bool   /* Verbose logging */
	endpoint string /* REST endpoint */
}

/* ServeHTTP handles requests for resolution */
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	/* Only serve the one path */
	if h.endpoint != r.URL.Path {
		http.NotFound(w, r)
		return
	}

	/* Parse the query */
	if err := r.ParseForm(); nil != err {
		h.Error(
			w,
			r,
			"Parse error: "+err.Error(),
			http.StatusBadRequest,
		)
		return
	}

	/* Make sure we have a name and type */
	qname := r.Form.Get(QNAME) /* Query name */
	if "" == qname {
		h.Error(w, r, "No name provided", http.StatusBadRequest)
		return
	}
	qtype := r.Form.Get(QTYPE) /* Query type */
	if "" == qtype {
		h.Error(w, r, "No query type provided", http.StatusBadRequest)
		return
	}

	/* Set the content-type in the response */
	ctype := r.Form.Get(CTYPE) /* Content-type */
	if "" == ctype {
		ctype = h.ctype
	}
	w.Header().Set("Content-Type", ctype)

	/* Do the lookup */
	ans, code, err := h.Lookup(qname, qtype)
	if nil != err {
		h.Error(w, r, err.Error(), code)
		return
	}

	/* If we're meant to make it pretty, do so */
	var res []byte
	if _, ok := r.Form[PRETTY]; ok {
		res, err = json.MarshalIndent(ans, "", "\t")
	} else {
		res, err = json.Marshal(ans)
	}
	if nil != err {
		h.Error(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	/* Send it back */
	if h.verbose {
		log.Printf(
			"[%v] %v %v %v %v %q",
			r.RemoteAddr,
			http.StatusOK,
			r.Method,
			r.Host,
			r.URL,
			ans.answerData(),
		)
	}
	w.Write(res)
	w.Write([]byte("\n"))
}

// Lookup performs a lookup for the given name and type and returns a Response
// struct.
func (h Handler) Lookup(qname, qtype string) (Response, int, error) {
	var (
		res = Response{
			TC:       false,
			RD:       true,
			RA:       true,
			AD:       false,
			CD:       false,
			Question: []Question{{Name: qname}},
		} /* Response to send back */
		qn  uint     /* QType as a number */
		as  []string /* Answers from upstream */
		err error
	)

	/* Proxy lookup upstream */
	switch strings.ToLower(qtype) {
	case "1", "a":
		qn = 1
		ips, e := net.LookupIP(qname)
		err = e
		/* Filter out AAAA records */
		as = make([]string, 0, len(ips))
		for _, ip := range ips {
			if f := ip.To4(); nil != f {
				as = append(as, f.String())
			}
		}
	case "2", "ns":
		qn = 2
		/* Because really what we need is a struct around a string */
		nss, e := net.LookupNS(qname)
		err = e
		as = make([]string, len(nss))
		for i, ns := range nss {
			as[i] = ns.Host
		}
	case "5", "cname":
		qn = 5
		as = make([]string, 1)
		as[0], err = net.LookupCNAME(qname)
	case "12", "ptr":
		qn = 12
		as, err = net.LookupAddr(qname)
	case "15", "mx":
		qn = 15
		mxs, e := net.LookupMX(qname)
		err = e
		/* Stringify the MX records */
		as = make([]string, len(mxs))
		for i, mx := range mxs {
			as[i] = fmt.Sprintf("%v %v", mx.Pref, mx.Host)
		}
	case "16", "txt":
		qn = 16
		as, err = net.LookupTXT(qname)
	case "28", "aaaa":
		qn = 28
		ips, e := net.LookupIP(qname)
		err = e
		/* Filter out A records */
		as = make([]string, 0, len(ips))
		for _, ip := range ips {
			if f := ip.To4(); nil == f {
				as = append(as, ip.String())
			}
		}
	case "33", "srv":
		qn = 33
		_, srvs, e := net.LookupSRV("", "", qname)
		err = e
		/* Unroll the SRV records */
		as = make([]string, len(srvs))
		for i, srv := range srvs {
			as[i] = fmt.Sprintf(
				"%v %v %v %v",
				srv.Priority,
				srv.Weight,
				srv.Port,
				srv.Target,
			)
		}
	default:
		return res, http.StatusNotImplemented, errors.New(
			"unsupported query type: " + qtype,
		)
	}
	if nil != err {
		return res, http.StatusInternalServerError, err
	}

	/* Fill in the rest of the question section */
	res.Question[0].Type = qn

	/* Add the answers */
	for _, a := range as {
		res.Answer = append(res.Answer, Answer{
			Name: qname,
			Type: qn,
			TTL:  h.ttl,
			Data: a,
		})
	}

	return res, 0, nil
}

// Error wraps http.Error with logging.
func (h Handler) Error(
	w http.ResponseWriter,
	r *http.Request,
	msg string,
	status int,
) {
	/* Error number */
	enum := make([]byte, 8)
	if _, err := rand.Read(enum); nil != err {
		log.Printf("Unable to read random bytes: %v", err)
	}

	/* Log a message if we're meant to */
	if h.verbose {
		log.Printf(
			"[%v] %v %v %v %v %v (error number %02x)",
			r.RemoteAddr,
			status,
			r.Method,
			r.Host,
			r.URL,
			msg,
			enum,
		)
	}
	http.Error(w, fmt.Sprintf("Error number %02x", enum), status)
}

func main() {
	var (
		cert = flag.String(
			"cert",
			"cert.pem",
			"TLS certificate `file`",
		)
		key = flag.String(
			"key",
			"key.pem",
			"TLS key `file`",
		)
		httpAddr = flag.String(
			"http",
			NO,
			"HTTP listen `address` or \""+NO+"\" to disable",
		)
		httpsAddr = flag.String(
			"https",
			"127.0.0.1:4433",
			"HTTPS listen `address`, or \""+NO+"\" to disable",
		)
		fcgiAddr = flag.String(
			"fcgi",
			NO,
			"FastCGI listen `address`, which may either "+
				"be a path or an ip:port, or \""+NO+"\" "+
				"to disable",
		)
		removeSock = flag.Bool(
			"remove-fcgi-socket",
			false,
			"Remove an existing FCGI socket before listening",
		)
		contentType = flag.String(
			"content-type",
			"application/json",
			"The default `MIME type` to send in responses",
		)
		ttl = flag.Uint(
			"ttl",
			1800,
			"TTL to return to clients, in `seconds`",
		)
		verbOn = flag.Bool(
			"v",
			false,
			"Enable verbose logging",
		)
		endpoint = flag.String(
			"endpoint",
			"/resolve",
			"REST endpoint `path` to serve",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Serves DNS over HTTPS queries.

Queries should be of the form /resolve?name=something.com&type=T[&content-type=type/type][&pp=]

The query parameters are as follows:
name:         The name for which to do a DNS query
type:         The resource record type to return
content-type: A custom Content-Type to use in the reply
pp:           Causes the response to be pretty-printed (i.e. indented)

Only queries of type A, NS, PTR, MX, TXT, AAAA, and SRV are supported

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Register handler */
	http.Handle(*endpoint, Handler{
		ctype:    *contentType,
		ttl:      *ttl,
		verbose:  *verbOn,
		endpoint: *endpoint,
	})

	/* Listen and serve */
	ech := make(chan error)
	go serveHTTP(ech, *httpAddr)
	go serveHTTPS(ech, *httpsAddr, *cert, *key)
	go serveFCGI(ech, *fcgiAddr, *removeSock)

	log.Fatalf("Fatalf error: %v", <-ech)
}

/* serveHTTP responds to HTTP queries */
func serveHTTP(ech chan<- error, addr string) {
	if "" == addr || NO == addr {
		return
	}
	/* Listen */
	l, err := net.Listen("tcp", addr)
	if nil != err {
		ech <- err
		return
	}
	log.Printf("Serving HTTP requests on %v", l.Addr())
	/* Serve */
	ech <- http.Serve(l, nil)
}

/* serveHTTPS responds to HTTPS queries */
func serveHTTPS(ech chan<- error, addr, cert, key string) {
	if "" == addr || NO == addr {
		return
	}
	/* Listen */
	l, err := net.Listen("tcp", addr)
	if nil != err {
		ech <- err
		return
	}
	log.Printf("Serving HTTPS requests on %v", l.Addr())
	/* Serve */
	ech <- http.ServeTLS(l, nil, cert, key)
}

/* serveFCGI responds to FCGI queries */
func serveFCGI(ech chan<- error, addr string, rmsock bool) {
	if "" == addr || NO == addr {
		return
	}
	/* Try as a TCP socket first */
	if ta, err := net.ResolveTCPAddr("tcp", addr); nil == err {
		/* Listen */
		l, err := net.ListenTCP("tcp", ta)
		if nil != err {
			ech <- err
			return
		}
		log.Printf("Serving FastCGI requests on %v", l.Addr())
		/* Serve */
		ech <- fcgi.Serve(l, nil)
		return
	}
	/* Failing that, treat as a unix socket */

	/* If the path exists and we're to remove it, remove it */
	if _, err := os.Stat(addr); rmsock && !os.IsNotExist(err) {
		if err := os.Remove(addr); nil != err {
			ech <- err
			return
		}
	}

	/* Listen */
	l, err := net.Listen("unix", addr)
	if nil != err {
		ech <- err
		return
	}
	if u, ok := l.(*net.UnixListener); ok {
		u.SetUnlinkOnClose(true)
	}
	log.Printf("Serving FastCGI requests on %v", l.Addr())

	/* Serve */
	ech <- fcgi.Serve(l, nil)
}
