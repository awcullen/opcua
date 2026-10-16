// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"net"
	"net/url"

	"github.com/awcullen/opcua/ua"
)

// A server bound to every interface (opc.tcp://0.0.0.0:port, opc.tcp://[::]:port) has an
// endpoint URL and discovery URL that no client can dial. FindServers, GetEndpoints and
// CreateSession answer with the host the client used instead, as OPC UA Part 4 §5.4.2 and
// §5.4.4 intend: the request's endpointUrl is "the network address that the Client used to
// access the DiscoveryEndpoint", and the Server uses it "to determine what URLs to return".
// A request that names no usable host gets the local address of the connection it came in
// on, which is an address of this server that the client reaches. A URL whose host is not
// unspecified is returned unchanged.

// isUnspecifiedHost reports whether host is empty or an unspecified IP address.
func isUnspecifiedHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// clientHost is the host to advertise to the client on conn: the host of requestedURL,
// else the local address of conn. It returns "" when neither names a host.
func clientHost(requestedURL string, conn net.Conn) string {
	if u, err := url.Parse(requestedURL); err == nil && !isUnspecifiedHost(u.Hostname()) {
		return u.Hostname()
	}
	if conn == nil {
		return ""
	}
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcp.IP != nil && !tcp.IP.IsUnspecified() {
		return tcp.IP.String()
	}
	return ""
}

// withHost returns rawURL with an unspecified host replaced by host, port kept.
// Any other URL, or an empty host, returns rawURL unchanged.
func withHost(rawURL, host string) string {
	if host == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || !isUnspecifiedHost(u.Hostname()) {
		return rawURL
	}
	if p := u.Port(); p != "" {
		u.Host = net.JoinHostPort(host, p)
	} else if net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u.String()
}

// describeFor returns a copy of d whose discovery URLs name host.
func describeFor(d ua.ApplicationDescription, host string) ua.ApplicationDescription {
	if len(d.DiscoveryURLs) == 0 {
		return d
	}
	urls := make([]string, len(d.DiscoveryURLs))
	for i, u := range d.DiscoveryURLs {
		urls[i] = withHost(u, host)
	}
	d.DiscoveryURLs = urls
	return d
}

// endpointsFor returns the server's endpoints as advertised to a client that asked with
// requestedURL on conn: each EndpointURL is requestedURL when it names a host (as before),
// else the configured URL with an unspecified host replaced by the client's host.
func (srv *Server) endpointsFor(requestedURL string, conn net.Conn) []ua.EndpointDescription {
	host := clientHost(requestedURL, conn)
	src := srv.Endpoints()
	eps := make([]ua.EndpointDescription, len(src))
	for i, ep := range src {
		if u, err := url.Parse(requestedURL); err == nil && !isUnspecifiedHost(u.Hostname()) {
			ep.EndpointURL = requestedURL
		} else {
			ep.EndpointURL = withHost(ep.EndpointURL, host)
		}
		ep.Server = describeFor(ep.Server, host)
		eps[i] = ep
	}
	return eps
}
