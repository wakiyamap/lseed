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

	macaroon "gopkg.in/macaroon.v1"

	log "github.com/Sirupsen/logrus"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/lseed/seed"
)

var (
	listenAddr = flag.String("listen", "0.0.0.0:53", "Listen address for incoming requests.")

	lndNode = flag.String("lnd-node", "localhost:10009", "The host:port of the backing lnd node")

	rootDomain = flag.String("root-domain", "nodes.lightning.directory", "Root DNS seed domain.")

	authoritativeIP = flag.String("root-ip", "127.0.0.1", "The IP address of the authoritative name server. This is used to create a dummy record which allows clients to access the seed directly over TCP")

	pollInterval = flag.Int("poll-interval", 30, "Time between polls to lightningd for updates")

	debug = flag.Bool("debug", false, "Be very verbose")

	numResults = flag.Int("results", 25, "How many results shall we return to a query?")
)

var (
	lndHomeDir             = btcutil.AppDataDir("lnd", false)
	defaultTLSCertFilename = "tls.cert"
	tlsCertPath            = filepath.Join(lndHomeDir, defaultTLSCertFilename)

	defaultMacaroonFilename = "readonly.macaroon"
	defaultMacaroonPath     = filepath.Join(lndHomeDir, defaultMacaroonFilename)
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
func initLightningClient() (lnrpc.LightningClient, error) {
	// First attempt to establish a connection to lnd's RPC sever.
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert file: %v", err)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// Load the specified macaroon file.
	macPath := cleanAndExpandPath(defaultMacaroonPath)
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

	conn, err := grpc.Dial(*lndNode, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to dial to lnd's gRPC server: ",
			err)
	}

	// If we're able to connect out to the lnd node, then we can start up
	// our RPC connection properly.
	lnd := lnrpc.NewLightningClient(conn)

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

	nview := seed.NewNetworkView()
	rootIP := net.ParseIP(*authoritativeIP)
	dnsServer := seed.NewDnsServer(nview, *listenAddr, *rootDomain,
		rootIP)

	lndNode, err := initLightningClient()
	if err != nil {
		log.Fatal("unable to connect to lnd: %v", err)
	}

	go poller(lndNode, nview)
	dnsServer.Serve()
}
