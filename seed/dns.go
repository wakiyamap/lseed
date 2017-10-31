// Copyright 2016 Christian Decker. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package seed

// Various utilities to help building and serializing DNS answers. Big
// shoutout to miekg for his dns library :-)

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcutil/bech32"
)

type DnsServer struct {
	netview         *NetworkView
	listenAddr      string
	rootDomain      string
	authoritativeIP net.IP
}

func NewDnsServer(netview *NetworkView, listenAddr, rootDomain string,
	authoritativeIP net.IP) *DnsServer {

	return &DnsServer{
		netview:         netview,
		listenAddr:      listenAddr,
		rootDomain:      rootDomain,
		authoritativeIP: authoritativeIP,
	}
}

func addAResponse(n Node, name string, responses *[]dns.RR) {
	header := dns.RR_Header{
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    60,
		Name:   name,
	}

	for _, a := range n.Addresses {

		if a.IP.To4() == nil {
			continue
		}

		rr := &dns.A{
			Hdr: header,
			A:   a.IP.To4(),
		}
		*responses = append(*responses, rr)
	}

}

func addAAAAResponse(n Node, name string, responses *[]dns.RR) {
	header := dns.RR_Header{
		Rrtype: dns.TypeAAAA,
		Class:  dns.ClassINET,
		Ttl:    60,
		Name:   name,
	}
	for _, a := range n.Addresses {

		if a.IP.To4() != nil {
			continue
		}

		rr := &dns.AAAA{
			Hdr:  header,
			AAAA: a.IP.To16(),
		}
		*responses = append(*responses, rr)
	}
}

func (ds *DnsServer) handleAAAAQuery(request *dns.Msg, response *dns.Msg) {
	nodes := ds.netview.RandomSample(3, 25)
	for _, n := range nodes {
		addAAAAResponse(n, request.Question[0].Name, &response.Answer)
	}
}

func (ds *DnsServer) handleAQuery(request *dns.Msg, response *dns.Msg) {
	nodes := ds.netview.RandomSample(2, 25)

	for _, n := range nodes {
		addAResponse(n, request.Question[0].Name, &response.Answer)
	}
}

// Handle incoming SRV requests.
//
// Unlike the A and AAAA requests these are a bit ambiguous, since the
// client may either be IPv4 or IPv6, so just return a mix and let the
// client figure it out.
func (ds *DnsServer) handleSRVQuery(request *dns.Msg, response *dns.Msg) {
	nodes := ds.netview.RandomSample(255, 25)

	header := dns.RR_Header{
		Name:   request.Question[0].Name,
		Rrtype: dns.TypeSRV,
		Class:  dns.ClassINET,
		Ttl:    60,
	}

	for _, n := range nodes {
		rawID, err := hex.DecodeString(n.Id)
		if err != nil {
			continue
		}

		convertedID, err := bech32.ConvertBits(rawID, 8, 5, true)
		if err != nil {
			log.Errorf("Unable to convert key=%x, %v", rawID, err)
			continue
		}
		encodedId, err := bech32.Encode("ln", convertedID)
		if err != nil {
			log.Errorf("Unable to encode key=%x, %v", convertedID, err)
			continue
		}

		nodeName := fmt.Sprintf("%s.%s.", encodedId, ds.rootDomain)
		rr := &dns.SRV{
			Hdr:      header,
			Priority: 10,
			Weight:   10,
			Target:   nodeName,
			Port:     uint16(n.Addresses[0].Port),
		}
		response.Answer = append(response.Answer, rr)
		//if n.Type&1 == 1 {
		//	addAAAAResponse(n, nodeName, &response.Extra)
		//} else {
		//	addAResponse(n, nodeName, &response.Extra)
		//}
	}

}

type DnsRequest struct {
	subdomain string
	qtype     uint16
	atypes    int
	realm     int
	node_id   string
}

func (ds *DnsServer) parseRequest(name string, qtype uint16) (*DnsRequest, error) {
	// Check that this is actually intended for us and not just some other domain
	name = strings.ToLower(name)
	if !strings.HasSuffix(strings.ToLower(name), fmt.Sprintf("%s.", ds.rootDomain)) {
		return nil, fmt.Errorf("malformed request: %s", name)
	}

	// Check that we actually like the request
	switch qtype {
	case dns.TypeA:
	case dns.TypeAAAA:
	case dns.TypeSRV:
	default:
		// If they don't query for any of our supported request types,
		// then we'll exit early with an error.
		return nil, fmt.Errorf("refusing to handle query type %d (%s)",
			qtype, dns.TypeToString[qtype])
	}

	req := &DnsRequest{
		subdomain: name[:len(name)-len(ds.rootDomain)-1],
		qtype:     qtype,
		atypes:    6,
	}
	parts := strings.Split(req.subdomain, ".")

	// If they're attempting to pool for the IP address of the
	// authoritative name server (us), then we'll return a slimmed down
	// request to indicate this.
	if req.subdomain == "soa." {
		return &DnsRequest{
			subdomain: req.subdomain,
		}, nil
	}

	for _, cond := range parts {
		if len(cond) == 0 {
			continue
		}
		k, v := cond[0], cond[1:]

		if k == 'r' {
			req.realm, _ = strconv.Atoi(v)
		} else if k == 'a' && qtype == dns.TypeSRV {
			req.atypes, _ = strconv.Atoi(v)
		} else if k == 'l' {
			_, bin5, err := bech32.Decode(cond)
			if err != nil {
				return nil, fmt.Errorf("malformed bech32 pubkey")
			}
			bin, err := bech32.ConvertBits(bin5, 5, 8, false)
			if err != nil {
				return nil, fmt.Errorf("unable to convert bits: %x", bin5)
			}

			p, err := btcec.ParsePubKey(bin, btcec.S256())
			if err != nil {
				return nil, fmt.Errorf("not a valid pubkey: %x", bin)
			}
			req.node_id = fmt.Sprintf("%x", p.SerializeCompressed())
		}
	}

	return req, nil
}

func (ds *DnsServer) handleLightningDns(w dns.ResponseWriter, r *dns.Msg) {

	if len(r.Question) < 1 {
		log.Errorf("empty request")
		return
	}

	req, err := ds.parseRequest(r.Question[0].Name, r.Question[0].Qtype)

	if err != nil {
		log.Errorf("error parsing request: %v", err)
		return
	}

	log.WithFields(log.Fields{
		"subdomain": req.subdomain,
		"type":      dns.TypeToString[req.qtype],
	}).Debugf("Incoming request")

	m := new(dns.Msg)
	m.SetReply(r)

	switch {
	// If they're requesting our SOA shim, then we'll directly return the
	// IP address of the authoritative DNS server for fallback TCP
	// purposes.
	case req.subdomain == "soa.":
		soaResp := &dns.A{
			Hdr: dns.RR_Header{
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
				Name:   r.Question[0].Name,
			},
			A: ds.authoritativeIP,
		}
		m.Answer = append(m.Answer, soaResp)

	// Is this a wildcard query? If so we'll either return: a set of
	// reachable IPv6 addresses, IPv4 addresses, or return a set of SRV
	// records that nodes can use to bootstrap to the network.
	case req.node_id == "":
		switch req.qtype {
		case dns.TypeAAAA:
			ds.handleAAAAQuery(r, m)
			break
		case dns.TypeA:
			log.Debugf("Wildcard query")
			ds.handleAQuery(r, m)
			break
		case dns.TypeSRV:
			ds.handleSRVQuery(r, m)
		}

	// If they're targeting a specific sub-domain (which targets a node on
	// the network), then we'll attempt to return a reachable IP address
	// for the target node.
	default:
		n, ok := ds.netview.reachableNodes[req.node_id]
		if !ok {
			log.Debugf("Unable to find node with ID %s", req.node_id)
		}

		// Reply with the correct type
		if req.qtype == dns.TypeAAAA {
			addAAAAResponse(n, r.Question[0].Name, &m.Answer)
		} else if req.qtype == dns.TypeA {
			addAResponse(n, r.Question[0].Name, &m.Answer)
		}
	}

	w.WriteMsg(m)
	log.WithField("replies", len(m.Answer)).Debugf(
		"Replying with %d answers and %d extras (len=%v)",
		len(m.Answer), len(m.Extra), m.Len())
}

func (ds *DnsServer) Serve() {
	dns.HandleFunc(ds.rootDomain, ds.handleLightningDns)

	// We'll launch goroutines to listen on both udp and tcp as some
	// clients may fallback to opening a direct connection to the
	// authoritative server in the case that their resolves have issues
	// with our large-ish responses over udp.
	go func() {
		udpServer := &dns.Server{Addr: ds.listenAddr, Net: "udp"}
		if err := udpServer.ListenAndServe(); err != nil {
			panic(fmt.Sprintf("failed to setup the udp "+
				"server: %s\n", err.Error()))
		}
	}()
	go func() {
		tcpServer := &dns.Server{Addr: ds.listenAddr, Net: "tcp"}
		if err := tcpServer.ListenAndServe(); err != nil {
			panic(fmt.Sprintf("failed to setup the tcp "+
				"server: %s\n", err.Error()))
		}
	}()

	quitChan := make(chan os.Signal)
	signal.Notify(quitChan, syscall.SIGINT, syscall.SIGTERM)
	<-quitChan
}
