package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	macaroon "gopkg.in/macaroon.v2"

	log "github.com/Sirupsen/logrus"
	"github.com/wakiyamap/lnd/lnrpc"
	"github.com/wakiyamap/lnd/macaroons"
	"github.com/wakiyamap/monautil"
	"github.com/wakiyamap/lseed/seed"
)

var (
	listenAddr = flag.String("listen", "0.0.0.0:53", "Listen address for incoming requests.")

	bitcoinNodeHost  = flag.String("btc-lnd-node", "", "The host:port of the backing btc lnd node")
	monacoinNodeHost = flag.String("mona-lnd-node", "", "The host:port of the backing mona lnd node")
	testNodeHost     = flag.String("test-lnd-node", "", "The host:port of the backing btc testlnd node")

	bitcoinTLSPath  = flag.String("btc-tls-path", "", "The path to the TLS cert for the btc lnd node")
	monacoinTLSPath = flag.String("mona-tls-path", "", "The path to the TLS cert for the mona lnd node")
	testTLSPath     = flag.String("test-tls-path", "", "The path to the TLS cert for the test lnd node")

	bitcoinMacPath  = flag.String("btc-mac-path", "", "The path to the macaroon for the btc lnd node")
	monacoinMacPath = flag.String("mona-mac-path", "", "The path to the macaroon for the mona lnd node")
	testMacPath     = flag.String("test-mac-path", "", "The path to the macaroon for the test lnd node")

	rootDomain = flag.String("root-domain", "nodes.lightning.directory", "Root DNS seed domain.")

	authoritativeIP = flag.String("root-ip", "127.0.0.1", "The IP address of the authoritative name server. This is used to create a dummy record which allows clients to access the seed directly over TCP")

	pollInterval = flag.Int("poll-interval", 180, "Time between polls to lightningd for updates")

	debug = flag.Bool("debug", false, "Be very verbose")

	numResults = flag.Int("results", 25, "How many results shall we return to a query?")
)

var (
	lndHomeDir = monautil.AppDataDir("lnd", false)
)

// cleanAndExpandPath expands environment variables and leading ~ in the passed
// path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(lndHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// initLightningClient attempts to initialize, and connect out to the backing
// lnd node as specified by the lndNode ccommand line flag.
func initLightningClient(nodeHost, tlsCertPath, macPath string) (lnrpc.LightningClient, error) {
	// First attempt to establish a connection to lnd's RPC sever.
	tlsCertPath = cleanAndExpandPath(tlsCertPath)
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert file: %v", err)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	// Load the specified macaroon file.
	macPath = cleanAndExpandPath(macPath)
	macBytes, err := ioutil.ReadFile(macPath)
	if err != nil {
		return nil, err
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}
	// Now we append the macaroon credentials to the dial options.
	opts = append(
		opts,
		grpc.WithPerRPCCredentials(macaroons.NewMacaroonCredential(mac)),
	)
	conn, err := grpc.Dial(nodeHost, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to dial to lnd's gRPC server: ",
			err)
	}
	// If we're able to connect out to the lnd node, then we can start up
	// our RPC connection properly.
	lnd := lnrpc.NewLightningClient(conn)

	// Before we proceed, make sure that we can query the target node.
	_, err = lnd.GetInfo(
		context.Background(), &lnrpc.GetInfoRequest{},
	)
	if err != nil {
		return nil, err
	}

	return lnd, nil
}

// poller regularly polls the backing lnd node and updates the local network
// view.
func poller(lnd lnrpc.LightningClient, nview *seed.NetworkView) {
	scrapeGraph := func() {
		graphReq := &lnrpc.ChannelGraphRequest{}
		graph, err := lnd.DescribeGraph(
			context.Background(), graphReq,
		)
		if err != nil {
			log.Debugf("Unable to query for graph: %v", err)
			return
		}

		log.Debugf("Got %d nodes from lnd", len(graph.Nodes))
		for _, node := range graph.Nodes {
			if len(node.Addresses) == 0 {
				continue
			}

			if _, err := nview.AddNode(node); err != nil {
				log.Debugf("Unable to add node: %v", err)
			}
		}
	}

	scrapeGraph()

	ticker := time.NewTicker(time.Second * time.Duration(*pollInterval))
	for range ticker.C {
		scrapeGraph()
	}
}

// Parse flags and configure subsystems according to flags
func configure() {
	flag.Parse()
	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

// Main entry point for the lightning-seed
func main() {
	log.SetOutput(os.Stdout)

	configure()

	netViewMap := make(map[string]*seed.ChainView)

	if *bitcoinNodeHost != "" && *bitcoinTLSPath != "" && *bitcoinMacPath != "" {
		log.Infof("Creating BTC chain view")

		lndNode, err := initLightningClient(
			*bitcoinNodeHost, *bitcoinTLSPath, *bitcoinMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to btc lnd: %v", err))
		}

		nView := seed.NewNetworkView("bitcoin")
		go poller(lndNode, nView)

		log.Infof("BTC chain view active")

		netViewMap[""] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}

	}

	if *monacoinNodeHost != "" && *monacoinTLSPath != "" && *monacoinMacPath != "" {
		log.Infof("Creating MONA chain view")

		lndNode, err := initLightningClient(
			*monacoinNodeHost, *monacoinTLSPath, *monacoinMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to mona lnd: %v", err))
		}

		nView := seed.NewNetworkView("monacoin")
		go poller(lndNode, nView)

		netViewMap[""] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}

	}
	if *testNodeHost != "" && *testTLSPath != "" && *testMacPath != "" {
		log.Infof("Creating BTC testnet chain view")

		lndNode, err := initLightningClient(
			*testNodeHost, *testTLSPath, *testMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to test lnd: %v", err))
		}

		nView := seed.NewNetworkView("testnet")
		go poller(lndNode, nView)

		log.Infof("TBCT chain view active")

		netViewMap["test."] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}
	}

	if len(netViewMap) == 0 {
		panic(fmt.Sprintf("must specify at least one node type"))
	}

	rootIP := net.ParseIP(*authoritativeIP)
	dnsServer := seed.NewDnsServer(
		netViewMap, *listenAddr, *rootDomain, rootIP,
	)

	dnsServer.Serve()
}
