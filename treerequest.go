/* Copyright (c) 2020, William R. Burdick Jr., Roy Riggs, and TEAM CTHLUHU
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

//Package treerequest block request protocol for ipfs
//
// Each peer can provide a set of persistent root nodes and their children.
//
// Other peers can ask for the CIDs of the trees and also any of the blocks.
//
// Access can be restricted to a set of peers.
//
// Known tree CIDs are stored in the data store you provide.
//
// For convenience, there are http services to access the trees given a prefix you provide that
// handle GET and (for your own peer) PUT requests with optional encryption for a provided URL prefix:
//   unencrypted access: /PREFIX/PEERID/PATH
//   encrypted access (only for your peer's files): /PREFIX/PATH
//
// Before using the package, you must call InitTreeRequest().
//
// IPFS-lite works well with TreeRequest and provides all of the required values for InitTreeRequest():
//   ipfslite.BadgerDatastore(PATH) returns a ds.Datastore
//   (*ipfslite.Peer).BlockStore() returns a blockstore.Blockstore
//   *ipfslite.Peer implements ipld.DAGService
//   (*ipfslite.Peer).Session(CTX) returns an ipld.NodeGetter
package treerequest

/* protocol to read blocks in a peer's ipns path (starting at this peer's ipns value)
 *
 * Requests:
 * CID:      [1][reqest-id: uint64][path: string] -- fetch a CID
 * Contents: [2][reqest-id: uint64][path: string] -- fetch an entire node
 *
 * Responses:
 * CID:      [1][request-id: uint64][CID: [32]bytes]
 * Contents: [2][request-id: uint64][block: []bytes]
 * Error:    [3][msg: string]
 */

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	pinner "github.com/ipfs/go-ipfs-pinner"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-unixfs"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	msgpack "github.com/vmihailenco/msgpack/v5"
	storage "github.com/zot/textcraft-treerequest/storage"
)

type blockPublishingError int
type blockRequestMessageType int

const (
	reqCID blockRequestMessageType = iota
	reqContents
	respCID
	respContents
	respError
)

var timeZero = time.Time{}
var pendingTrees = make(map[string][]chan RequestResult)
var errEncoding = fmt.Errorf("Encoding error with stored tree")
var errNoConnection = fmt.Errorf("Could not connect to peer")
var errDecoding = fmt.Errorf("Could not decode file")
var errDecrypting = fmt.Errorf("Could not decrypt file")
var conf struct {
	protocol           protocol.ID
	host               host.Host
	bstor              blockstore.Blockstore
	dstor              ds.Datastore
	getter             ipld.NodeGetter
	dag                ipld.DAGService // required for creating directories
	conSvc             chan func()
	connections        map[peer.ID]*connection
	peers              map[peer.ID]bool
	myTrees            map[string]*CidTree // stored in the datastore under this host's peerID/name
	peerKey            p2pcrypto.PrivKey
	rsaKey             *rsa.PrivateKey
	cert               *x509.Certificate
	connectionCallback func(peer.ID)
	lastRefresh        map[peer.ID]time.Time
	pin                pinner.Pinner
	announced          map[cid.Cid]bool
}

//message a blockRequest message
type message interface {
	getMessageType() blockRequestMessageType
	getID() uint64
	// process is called in its own goroutine
	process(con *connection, root message) error
	decode(con *connection) error
}

type response interface {
	self() response
}

type connection struct {
	stream       network.Stream
	decoder      *msgpack.Decoder
	encoder      *msgpack.Encoder
	req          chan message
	svc          chan func()
	requestID    uint64
	openRequests map[uint64]chan message
	serve        bool
}

//CidTree a CID tree for a peer
type CidTree struct {
	Nodes     map[string]cid.Cid
	FileNodes []cid.Cid
}

type msgRequest interface {
	supportsRequest()
}
type MsgBase struct {
	ID uint64
}
type msgRequestTree struct {
	MsgBase
	Tree string
}
type msgRequestContents struct {
	MsgBase
	NodeCids [][]byte
	Tree     string
}
type msgResponseTree struct {
	MsgBase
	CidTree
}
type msgResponseContents struct {
	MsgBase
	Contents [][]byte
	Missing  [][]byte
}
type msgError struct {
	MsgBase
	Msg string
}

//RequestResult result for an asynchronous request
type RequestResult struct {
	Tree *CidTree
	Err  error
}

//Root get the CidTree root
func (tree CidTree) Root() cid.Cid {
	return tree.Nodes["/"]
}

//AllCids get a map of Cid->true for all Cids in the tree
func (tree CidTree) AllCids() (allCids map[cid.Cid]bool) {
	allCids = make(map[cid.Cid]bool)
	for _, aCid := range tree.Nodes {
		allCids[aCid] = true
	}
	for _, aCid := range tree.FileNodes {
		allCids[aCid] = true
	}
	return
}

//AllNodes get a map of Node->true for all Nodes in the tree
func (tree CidTree) AllNodes() (allNodes map[cid.Cid]ipld.Node, err error) {
	allNodes = make(map[cid.Cid]ipld.Node)
	for aCid := range tree.AllCids() {
		block, err := conf.bstor.Get(aCid)
		if err == blockstore.ErrNotFound {
			fmt.Println("### NODE NOT FOUND FOR CID:", aCid)
			continue
		}
		if err != nil {return nil, err}
		node, err := ipld.Decode(block)
		if err != nil {return nil, err}
		allNodes[aCid] = node
	}
	return
}

func newMessage(typ blockRequestMessageType) (message, error) {
	switch typ {
	case reqCID:
		return new(msgRequestTree), nil
	case reqContents:
		return new(msgRequestContents), nil
	case respCID:
		return new(msgResponseTree), nil
	case respContents:
		return new(msgResponseContents), nil
	case respError:
		return new(msgError), nil
	default:
		return nil, fmt.Errorf("bad message type: %d", typ)
	}
}
func (msg *MsgBase) getMessageType() blockRequestMessageType { return -1 }
func (msg *MsgBase) decode(con *connection) error            { return con.decode(msg) }
func (msg *MsgBase) getID() uint64                           { return msg.ID }
func (msg *MsgBase) process(con *connection, root message) error {
	var err error
	svcSync(con.svc, func() {
		reqChan := con.openRequests[msg.ID]
		if reqChan == nil {
			err = fmt.Errorf("response for missing message id: %d", msg.ID)
		} else {
			delete(con.openRequests, msg.ID)
			reqChan <- root
		}
	})
	return err
}
func (msg *msgRequestTree) getMessageType() blockRequestMessageType { return reqCID }
func (msg *msgRequestTree) decode(con *connection) error            { return con.decode(msg) }
func (msg *msgRequestTree) supportsRequest()                        {}
func (msg *msgRequestTree) process(con *connection, root message) (err error) {
	var tree *CidTree
	fmt.Printf("REQUEST TREE: %p, BASE: %p\n", msg, &msg.MsgBase)
	if tree, err = con.getTree(msg.ID, msg.Tree); err != nil {return}
	return con.write(&msgResponseTree{
		MsgBase{msg.ID},
		*tree,
	})
}
func (msg *msgRequestContents) getMessageType() blockRequestMessageType { return reqContents }
func (msg *msgRequestContents) decode(con *connection) error            { return con.decode(msg) }
func (msg *msgRequestContents) supportsRequest()                        {}
func (msg *msgRequestContents) process(con *connection, root message) (err error) {
	var aCid cid.Cid
	var tree *CidTree
	contents := make([][]byte, 0, len(msg.NodeCids))
	missing := make([][]byte, 0, len(msg.NodeCids))
	if tree, err = con.getTree(msg.ID, msg.Tree); err != nil {return}
	allCids := tree.AllCids()
	for _, bytes := range msg.NodeCids {
		aCid, err = cid.Cast(bytes)
		if err != nil {return fmt.Errorf("error decoding requested CID in msg %d: %w", msg.ID, err)}
		if allCids[aCid] {
			blk, err := conf.bstor.Get(aCid)
			if err != nil {return err}
			contents = append(contents, blk.RawData())
		} else {
			missing = append(missing, bytes)
		}
	}
	err = con.write(&msgResponseContents{
		MsgBase{msg.ID},
		contents,
		missing,
	})
	return
}
func (msg *msgResponseTree) getMessageType() blockRequestMessageType { return respCID }
func (msg *msgResponseTree) decode(con *connection) error            { return con.decode(msg) }

func (msg *msgResponseContents) getMessageType() blockRequestMessageType { return respContents }
func (msg *msgResponseContents) decode(con *connection) error            { return con.decode(msg) }

func (msg *msgError) getMessageType() blockRequestMessageType { return respError }
func (msg *msgError) decode(con *connection) error            { return con.decode(msg) }
func (msg *msgError) Error() string                           { return msg.Msg }

func newConnection(str network.Stream, serve bool) *connection {
	return &connection{
		str,
		msgpack.NewDecoder(str),
		msgpack.NewEncoder(str),
		make(chan message),
		make(chan func()),
		0,
		make(map[uint64]chan message),
		serve,
	}
}

//InitTreeRequest ipfslite provides route (dht is a routing.ValueStore) and ds
func InitTreeRequest(protocolName string, dstor ds.Datastore, inputHost host.Host, peerKey *rsa.PrivateKey, peerCert *x509.Certificate, bstor blockstore.Blockstore, getter ipld.NodeGetter, dagService ipld.DAGService, pin pinner.Pinner, cacheSize int, trees map[string]cid.Cid, ensureTrees map[string]bool, newConnection func(peer.ID)) error {
	var err error
	if conf.protocol != "" {return fmt.Errorf("attempt to initialize treerequest more than once")}
	if protocolName == "" {return fmt.Errorf("attempt to initialize treerequest with no protocol")}
	conf.protocol = protocol.ID(protocolName)
	conf.bstor = bstor
	conf.host = inputHost
	conf.dstor = dstor
	conf.getter = getter
	conf.dag = dagService
	conf.conSvc = make(chan func(), 10)
	conf.connections = make(map[peer.ID]*connection)
	conf.peers = make(map[peer.ID]bool)
	conf.rsaKey = peerKey
	conf.cert = peerCert
	conf.connectionCallback = newConnection
	conf.pin = pin
	conf.announced = make(map[cid.Cid]bool)
	conf.lastRefresh = make(map[peer.ID]time.Time)
	go func() { // start conf service
		for code := range conf.conSvc {
			code()
		}
	}()
	if trees == nil {
		fmt.Println("###\n### CLEARING TREE\n###")
		err := dstor.Delete(keyForPeer("myTrees", "", inputHost.ID()))
		if err != ds.ErrNotFound {return err}
		conf.myTrees = make(map[string]*CidTree)
	} else {
		fmt.Println("###\n### NOT CLEARING TREE\n###")
		myTreeBytes, err := dstor.Get(keyForPeer("myTrees", "", inputHost.ID()))
		if err == ds.ErrNotFound { // no tree in storage
			conf.myTrees = make(map[string]*CidTree)
		} else if err != nil {
			return fmt.Errorf("error accessing storage: %w", err)
		} else { // unmarshal tree
			err = msgpack.Unmarshal(myTreeBytes, &conf.myTrees)
			if err != nil {return fmt.Errorf("error decoding tree from storage: %w", err)}
		}
		if len(conf.myTrees) == 1 {
			fmt.Println("###\n### Found 1 tree\n###")
		} else {
			fmt.Printf("###\n### Found %d trees\n###\n", len(conf.myTrees))
		}
		if len(trees) > 0 {
			for name, tree := range trees {
				fmt.Println("###\n### Storing new tree for peer:", tree, "name:", name, "\n###")
				err = SetTree(name, tree)
				if err != nil {return err}
			}
			err = Checkpoint()
			if err != nil {return err}
		} else {
			fmt.Println("###\n### No trees to store\n###")
		}
	}
	err = ensureEmptyTrees(ensureTrees)
	if err != nil {return err}
	err = findRefs()
	if err != nil {return err}
	conf.host.SetStreamHandler(conf.protocol, func(stream network.Stream) {
		fmt.Println("###\n### CONNECTION FROM", stream.Conn().RemotePeer())
		if conf.peers[stream.Conn().RemotePeer()] {
			fmt.Println("###\n### CONNECTION FROM FRIEND", stream.Conn().RemotePeer())
			runProtocol(stream, true)
		} else {
			// terminate connections from the uninvited
			fmt.Println("###\n### REFUSING CONNECTION FROM UNINVITED PEER", stream.Conn().RemotePeer())
			err := stream.Close()
			if err != nil {
				fmt.Printf("Error closing uninvited stream: %v\n", err)
			}
		}
	})
	return nil
}

func ensureEmptyTrees(ensure map[string]bool) error {
	var emptyDir cid.Cid

	for treeName := range ensure {
		if conf.myTrees[treeName] == nil {
			if emptyDir == cid.Undef {
				node := unixfs.EmptyDirNode()
				err := conf.bstor.Put(node)
				if err != nil {return err}
				emptyDir = node.Cid()
			}
			tree := NewCidTree(0)
			tree.Nodes["/"] = emptyDir
			conf.myTrees[treeName] = tree
		}
	}
	if emptyDir != cid.Undef {return Checkpoint()}
	return nil
}

//make sure all trees in storage are pinned
func findRefs() error {
	pins, err := conf.pin.DirectKeys(context.Background())
	if err != nil {return err}
	for _, aCid := range pins {
		err = conf.pin.Unpin(context.Background(), aCid, false)
		if err != nil && err != pinner.ErrNotPinned {return err}
	}
	pins, err = conf.pin.RecursiveKeys(context.Background())
	if err != nil {return err}
	for _, aCid := range pins {
		err = conf.pin.Unpin(context.Background(), aCid, true)
		if err != nil && err != pinner.ErrNotPinned {return err}
	}
	results, err := queryAll("tree")
	if err != nil {return err}
	es, err := results.Rest()
	if err != nil {return err}
	for _, e := range es {
		var tree CidTree
		err = msgpack.Unmarshal(e.Value, &tree)
		if err != nil {return err}
		node, err := fetchNode(tree.Root())
		if err != nil {return err}
		err = conf.pin.Pin(context.Background(), node, true)
		if err != nil {return err}
	}
	return nil
}

//ChangePeers add and/or remove peers
func ChangePeers(treeName string, add []peer.ID, remove []peer.ID) {
	for _, peerID := range add {
		conf.peers[peerID] = true
		refreshTree(peerID, treeName)
	}
	for _, peer := range remove {
		delete(conf.peers, peer)
	}
}

func refreshTree(peerID peer.ID, name string) {
	if shouldRefresh(peerID) {
		cur, _ := GetTree(peerID, name)
		addPendingRequest(peerID, name, true)
		requestTree(peerID, name, cur)
	}
}

//Checkpoint store the current trees
func Checkpoint() error {
	myTreeBytes, err := msgpack.Marshal(&conf.myTrees)
	if err != nil {return fmt.Errorf("error encoding tree for storage: %w", err)}
	err = conf.dstor.Put(keyForPeer("myTrees", "", conf.host.ID()), myTreeBytes)
	if err != nil {return fmt.Errorf("error storing tree: %w", err)}
	fmt.Println("Stored tree")
	return nil
}

func svcSync(svc chan func(), code func()) {
	done := make(chan bool)
	svcAsync(svc, func() {
		code()
		done <- true
	})
	<-done
}

//var svcCount = 0

func svcAsync(svc chan func(), code func()) {
	//count := svcCount
	//stack := debug.Stack()
	//svcCount++
	//fmt.Fprintf(os.Stderr, "#####\n### Sending SVC call %s\n", count)
	//os.Stderr.Write(stack)
	svc <- func() {
		//fmt.Fprintf(os.Stderr, "#####\n### Executing SVC call%s\n", count)
		//os.Stderr.Write(stack)
		code()
	}
}

func (con connection) svcSync(code func()) {
	svcSync(con.svc, code)
}

//this runs inside con's svc goroutine
func (con connection) newRequest() (MsgBase, chan message) {
	var id uint64
	response := make(chan message)
	con.svcSync(func() {
		con.requestID++
		id = con.requestID
		con.openRequests[id] = response
	})
	return MsgBase{id}, response
}

//FetchSync synchronously get the latest tree from a peer
func FetchSync(peerID peer.ID, name string) (*CidTree, error) {
	results := Fetch(peerID, name)
	result := <-results
	fmt.Printf("GOT RESULT %v\n", result)
	return result.Tree, result.Err
}

//Fetch get the latest tree from a peer
func Fetch(peerID peer.ID, name string) (done chan RequestResult) {
	fmt.Println("###\n### CHECKING FOR PENDING REQUESTS\n###")
	var myTree *CidTree
	svcSync(conf.conSvc, func() {
		if peerID == conf.host.ID() {
			myTree = conf.myTrees[name]
		}
	})
	if done = addPendingRequest(peerID, name, false); done != nil {
		fmt.Println("THERE IS ALREADY A REQUEST IN PROGRESS, WAITING FOR RESULT...")
		return
	}
	if peerID == conf.host.ID() {
		done = make(chan RequestResult, 1)
		if myTree == nil {
			done <- RequestResult{nil, fmt.Errorf("no tree named %s", name)}
		} else {
			done <- RequestResult{myTree, nil}
		}
		return
	}
	fmt.Println("###\n### CHECKING FOR TREE\n###")
	tree, err := GetTree(peerID, name) // check if we already have a tree
	if err == errEncoding {
		fmt.Printf("###\n### ERROR GETTING TREE: %s, REMOVING AND REQUESTING\n###\n", err.Error())
		_ = conf.dstor.Delete(keyForPeer("tree", name, peerID))
	} else if err != nil && err != ds.ErrNotFound {
		fmt.Printf("###\n### ERROR GETTING TREE: %v\n###\n", err)
		done <- RequestResult{tree, err}
	} else {
		fmt.Printf("###\n### FOUND TREE: %v, REQUESTING UPDATE\n###\n", tree)
	}
	fmt.Printf("###\n### REQUESTING TREE: %s, %s\n###\n", peerID.Pretty(), name)
	done = addPendingRequest(peerID, name, true)
	requestTree(peerID, name, tree)
	return
}

func shouldRefresh(peerID peer.ID) bool {
	var refresh bool
	svcSync(conf.conSvc, func() {
		refresh = conf.lastRefresh[peerID].Add(30 * time.Second).Before(time.Now())
	})
	return refresh
}

// done within tree service
func requestTree(peerID peer.ID, name string, oldTree *CidTree) {
	svcSync(conf.conSvc, func() {
		conf.lastRefresh[peerID] = time.Now()
	})
	go func() {
		err := ensureConnection(peerID)
		if err != nil {
			//finished(name, peerID, nil, false, fmt.Errorf("Could not connect to peer %s: %w", peerID.Pretty(), err))
			finished(name, peerID, oldTree, false, err)
			return
		}
		tree := oldTree
		stream, err := conf.host.NewStream(context.Background(), peerID, conf.protocol)
		if err == nil {
			con := runProtocol(stream, false)
			base, result := con.newRequest()
			err = con.write(&msgRequestTree{base, name})
			if err == nil {
				resp := <-result
				fmt.Printf("###\n### RESPONSE: %#v\n###\n", resp)
				if msg, ok := resp.(*msgResponseTree); ok {
					tree = &msg.CidTree
				} else if err, ok = resp.(*msgError); !ok {
					err = fmt.Errorf("unexpected response: %v", msg)
				}
				if err == nil && (oldTree == nil || oldTree.Root() != tree.Root()) { // fetch new blocks
					fetching, err := con.fetchUnknownBlocks(name, tree, oldTree)
					if err == nil && fetching {
						fmt.Println("FETCHING BLOCKS FOR TREE")
						return
					}
				}
			}
		}
		if err != nil {
			tree = oldTree
		}
		finished(name, peerID, tree, tree != nil && (oldTree == nil || oldTree.Root() != tree.Root()), err)
	}()
}

func ensureConnection(peerID peer.ID) error {
	con := conf.host.Network().Connectedness(peerID)
	switch con {
	case network.CannotConnect:
		fmt.Println("UNABLE TO CONNECT TO", peerID.Pretty())
		//return fmt.Errorf("unable to attempt connection to %s", peerID.Pretty())
		return errNoConnection
	case network.CanConnect, network.NotConnected:
		ma, err := ma.NewMultiaddr("/p2p/" + peerID.Pretty())
		if err != nil {return err}
		addr, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {return err}
		fmt.Println("Connecting to peer", peerID.Pretty())
		ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		err = conf.host.Connect(ctx, *addr)
		//if err != nil {return err}
		if err != nil {return errNoConnection}
		con := conf.host.Network().Connectedness(peerID)
		if con == network.Connected {
			fmt.Println("CONNECTED")
		} else {
			fmt.Println("FAILED TO CONNECT")
			//return fmt.Errorf("failed to connect to peer: %s", peerID.Pretty())
			return errNoConnection
		}
	case network.Connected:
		fmt.Println("ALREADY CONNECTED TO", peerID.Pretty())
	default:
		fmt.Println("UNKNOWN CONNECTEDNESS:", con)
		return fmt.Errorf("failed to connect to peer: %s", peerID.Pretty())
	}
	return nil
}

func finished(name string, peerID peer.ID, tree *CidTree, store bool, err error) {
	fmt.Printf("FINISHING REQUEST FOR %s/%s\n", peerID.Pretty(), name)
	if err == nil && store { // if requested, make sure the tree is stored before sending result
		err = tree.store(name, peerID)
	}
	if err == errNoConnection {
		err = nil
	} else if err != nil {
		tree = nil
	}
	pending := getPendingRequests(peerID, name)
	result := RequestResult{tree, err}
	fmt.Printf("SENDING RESULT %v TO %v\n", result, pending)
	for _, channel := range pending {
		channel <- result
	}
}
func checkBlockFetch(aCid cid.Cid, fetch [][]byte) ([][]byte, error) {
	has, err := conf.bstor.Has(aCid)
	if err != nil {return nil, err}
	if !has {return append(fetch, aCid.Bytes()), nil}
	return fetch, nil
}

func (con connection) fetchUnknownBlocks(name string, tree *CidTree, oldTree *CidTree) (bool, error) {
	var err error
	fetch := make([][]byte, 0, len(tree.Nodes))
	for _, aCid := range tree.Nodes {
		fetch, err = checkBlockFetch(aCid, fetch)
		if err != nil {return false, err}
	}
	for _, aCid := range tree.FileNodes {
		fetch, err = checkBlockFetch(aCid, fetch)
		if err != nil {return false, err}
	}
	if len(fetch) > 0 {
		base, result := con.newRequest()
		err = con.write(&msgRequestContents{base, fetch, name})
		if err != nil {return false, err}
		go func() {
			defer func() {
				if err == nil {
					finished(name, con.stream.Conn().RemotePeer(), tree, true, nil)
				} else if oldTree != nil {
					finished(name, con.stream.Conn().RemotePeer(), oldTree, false, nil)
				} else {
					finished(name, con.stream.Conn().RemotePeer(), nil, false, err)
				}
			}()
			resp := <-result
			if msg, ok := resp.(*msgResponseContents); ok {
				now := time.Now()
				var nowBytes [8]byte
				binary.BigEndian.PutUint64(nowBytes[:], uint64(now.Unix()))
				for _, item := range msg.Contents { // store the blocks
					block := blocks.NewBlock(item)
					err = conf.bstor.Put(block)
					if err != nil {return}
					err = conf.dstor.Put(timeKey(block.Cid()), nowBytes[:])
					if err != nil {return}
				}
			} else if msgErr, ok := resp.(*msgError); ok {
				err = msgErr
			} else {
				err = fmt.Errorf("unexpected response: %v", msg)
			}
		}()
	}
	return len(fetch) > 0, nil
}

func addPendingRequest(peerID peer.ID, name string, init bool) (req chan RequestResult) {
	svcSync(conf.conSvc, func() {
		key := peerID.Pretty() + "/" + name
		if pendingTrees[key] == nil {
			if !init {return}
			pendingTrees[key] = make([]chan RequestResult, 0, 4)
		}
		req = make(chan RequestResult)
		pendingTrees[key] = append(pendingTrees[key], req)
		fmt.Println("###\n### QUEUING RESPONSE CHANNEL\n###")
	})
	return
}

func getPendingRequests(peerID peer.ID, name string) (pending []chan RequestResult) {
	svcSync(conf.conSvc, func() {
		key := peerID.Pretty() + "/" + name
		pending = pendingTrees[key]
		delete(pendingTrees, key)
		if pending != nil {
			fmt.Printf("RETRIEVED PENDING CHANNELS FOR %s\n", key)
		} else {
			fmt.Printf("NO PENDING CHANNELS FOR %s\n", key)
		}
	})
	return
}

func timeKey(aCid cid.Cid) ds.Key {
	return ds.NewKey("time-" + aCid.KeyString())
}

//TimeForBlock get the time a block was stored
func TimeForBlock(blockCid cid.Cid) (time.Time, error) {
	timeBytes, err := conf.dstor.Get(timeKey(blockCid))
	if err != nil {return timeZero, err}
	timeVal := binary.BigEndian.Uint64(timeBytes)
	return time.Unix(int64(timeVal), 0), nil
}

func keyForPeer(prefix string, name string, peerID peer.ID) ds.Key {
	return ds.NewKey("textcraft-treerequest, " + prefix + ": " + string(conf.protocol) + "." + peerID.Pretty() + "/" + name + ":")
}

func queryAll(prefix string) (query.Results, error) {
	return conf.dstor.Query(query.Query{Prefix: "textcraft-treerequest, " + prefix + ": "})
}

//GetTree gets a tree from storage or returns an error if it's not there
func GetTree(peerID peer.ID, name string) (*CidTree, error) {
	var tree CidTree
	bytes, err := conf.dstor.Get(keyForPeer("tree", name, peerID))
	if err != nil {return nil, err}
	err = msgpack.Unmarshal(bytes, &tree)
	if err != nil {return nil, errEncoding}
	return &tree, err
}

func (tree CidTree) store(name string, peerID peer.ID) (err error) {
	var bytes []byte
	err = tree.changeRefs(name, peerID)
	if err != nil {return}
	bytes, err = msgpack.Marshal(&tree)
	if err == nil {
		err = conf.dstor.Put(keyForPeer("tree", name, peerID), bytes)
	}
	return
}

func (tree CidTree) changeRefs(name string, peerID peer.ID) error {
	oldTree, err := GetTree(peerID, name)
	if err != nil {return err}
	if oldTree != nil && tree.Root() != oldTree.Root() {
		err := conf.pin.Update(context.Background(), oldTree.Root(), tree.Root(), true)
		if err != nil {return err}
	} else {
		node, err := fetchNode(tree.Root())
		if err != nil {return err}
		err = conf.pin.Pin(context.Background(), node, true)
		if err != nil {return err}
	}
	return nil
}

//NewCidTree make a new, initialized cidtree
func NewCidTree(fileBlocks int) *CidTree {
	tree := CidTree{}
	tree.init(fileBlocks)
	return &tree
}

func (tree *CidTree) init(fileBlocks int) {
	cap := fileBlocks
	if fileBlocks == 0 {
		cap = 16
	}
	tree.Nodes = make(map[string]cid.Cid)
	tree.FileNodes = make([]cid.Cid, fileBlocks, cap)
}

func runProtocol(stream network.Stream, serve bool) (con *connection) {
	con = newConnection(stream, serve)
	go conf.connectionCallback(stream.Conn().RemotePeer())
	go func() {
		var err error
		svcAsync(conf.conSvc, func() {
			conf.connections[stream.Conn().RemotePeer()] = con
		})
		req := con.processPackets()
		err = con.stream.SetReadDeadline(timeZero)
		for err == nil { // process packets until an error
			err = con.readPacket(req)
		}
		if err != nil && err != io.EOF {
			fmt.Println("could not decode packet:", err.Error())
			_ = con.streamError(0, err)
		}
		err = con.close()
		if err != nil {
			fmt.Printf("Error closing connection: %v\n", err)
		}
	}()
	return
}

func (con connection) getPeer() peer.ID {
	return con.stream.Conn().RemotePeer()
}

func (con connection) close() error {
	close(con.req)
	close(con.svc)
	return con.stream.Close()
}

func (con connection) decode(value interface{}) error {
	//_, err := packet.Decode(con.decoder, value)
	return con.decoder.Decode(value)
}

func (con *connection) readPacket(req chan message) (err error) {
	var msgType uint8
	var msg message
	msgType, err = con.decoder.DecodeUint8()
	if err != nil {return}
	msg, err = newMessage(blockRequestMessageType(msgType))
	if err != nil {return}
	//_, err = packet.Decode(con.decoder, msg.ptr())
	err = msg.decode(con)
	if err != nil {return}
	req <- msg
	return
}

func (con *connection) processPackets() (messageChan chan message) {
	messageChan = make(chan message)
	go func() {
		for code := range con.svc {
			code()
		}
	}()
	go func() {
		for req := range messageChan {
			fmt.Printf("RECEIVED MESSAGE: %#v\n", req)
			var err error
			_, isRequest := req.(msgRequest)
			if !con.serve && isRequest {
				err = fmt.Errorf("received request on a non-serving connection %v", req)
			} else {
				err = req.process(con, req)
			}
			if err != nil {
				if err != io.EOF {
					fmt.Printf("Error processing message: %s\n", err.Error())
					_ = con.streamError(req.getID(), err)
					err = con.stream.Close()
					if err != nil {
						fmt.Printf("Error closing stream: %v\n", err)
					}
				}
				return
			}
		}
	}()
	return
}

func (con connection) write(msg message) (err error) {
	var buf []byte
	err = con.stream.SetWriteDeadline(timeZero)
	if err != nil {return}
	//buf, err = packet.Marshal(msg)
	buf, err = msgpack.Marshal(msg)
	if err != nil {return}
	fmt.Printf("SENDING MESSAGE[%s]: %#v\n", con.stream.Conn().RemotePeer(), msg)
	typeBuf := []byte{byte(msg.getMessageType())}
	_, err = con.stream.Write(typeBuf)
	if err != nil {return}
	_, err = bytes.NewBuffer(buf).WriteTo(con.stream)
	return
}

func (con connection) getTree(id uint64, name string) (*CidTree, error) {
	if conf.myTrees[name] == nil {return nil, con.streamError(id, fmt.Errorf("no tree named %s", name))}
	return conf.myTrees[name], nil
}

func (con connection) streamError(id uint64, err error) error {
	err = con.write(&msgError{MsgBase{id}, err.Error()})
	if err == nil {
		err = con.stream.Close()
	}
	if err != nil {
		fmt.Printf("%v", err)
	}
	return err
}

//SetTree set my tree to root, root must name a unixfs node
func SetTree(name string, root cid.Cid) error {
	tree := &CidTree{}
	tree.init(0)
	err := tree.findNodes("/", root, false)
	if err != nil {return fmt.Errorf("Error finding nodes from root %v: %w", root, err)}
	err = tree.store(name, conf.host.ID())
	if err != nil {return fmt.Errorf("Error storing tree %v: %w", root, err)}
	svcSync(conf.conSvc, func() {
		conf.myTrees[name] = tree
	})
	if err != nil {return err}
	return nil
}

func (tree CidTree) findNodes(urlPath string, aCid cid.Cid, file bool) error {
	node, err := fetchNode(aCid)
	if err != nil {return err}
	if !file {
		urlPath = path.Clean("/" + urlPath)
		fmt.Printf("Fetching node: %s: %s\n", urlPath, aCid)
		tree.Nodes[urlPath] = node.Cid()
		fsnode, err := unixfs.ExtractFSNode(node) // extract fs node to check if it's a directory
		if err != nil {return err}
		if fsnode.IsDir() {
			urlPath += "/"
			for _, link := range node.Links() {
				if link.Name != "" {
					err := tree.findNodes(urlPath+link.Name, link.Cid, false)
					if err != nil {return err}
				}
			}
		} else {
			file = true
		}
	} else {
		tree.FileNodes = append(tree.FileNodes, node.Cid())
	}
	if file {
		for _, link := range node.Links() {
			if link.Name != "" {
				err := tree.findNodes("", link.Cid, true)
				if err != nil {return err}
			}
		}
	}
	return nil
}

func fetchNode(aCid cid.Cid) (node ipld.Node, err error) {
	node, err = localNode(aCid)
	if node != nil || err != nil {return}
	return conf.dag.Get(context.Background(), aCid)
}

func localNode(aCid cid.Cid) (ipld.Node, error) {
	block, err := conf.bstor.Get(aCid)
	if err == blockstore.ErrNotFound {return nil, nil}
	if err != nil {return nil, err}
	node, err := ipld.Decode(block)
	if err != nil {return nil, err}
	return node, nil
}

//HandlePeerFileRequests install a PeerFileRequestHandler in the standard http server
func HandlePeerFileRequests(prefix string, encrypted bool, published func(path string, treeCid cid.Cid)) {
	http.HandleFunc(prefix, PeerFileRequestHandler(prefix, encrypted, published))
}

//PeerTreeFromURL get a peerID, treeName, and the remainder from a URL
func PeerTreeFromURL(urlPath string) (peer.ID, string, string, error) {
	fmt.Println("PARSE URL", urlPath)
	pind := strings.Index(urlPath, "/")
	peerID, err := peer.Decode(urlPath[0:pind])
	if err != nil {return peer.ID(""), "", "", fmt.Errorf("Bad peer id in request: %s, should be PEER/TREENAME", urlPath)}
	nind := pind + 1 + strings.Index(urlPath[pind+1:], "/")
	if nind < pind+1 {
		nind = len(urlPath)
	}
	treeName := urlPath[pind+1 : nind]
	if treeName == "" {return peer.ID(""), "", "", fmt.Errorf("Empty tree name in request: %s, should be PEER/TREENAME", urlPath)}
	return peerID, treeName, path.Clean("/" + urlPath[nind:]), nil
}

//PeerFileRequestHandler returns a handler for tree requests
//
// GET paths are of the form TREE/PEER-ID/PATH
//
// PUT paths are of the form TREE/PATH and are written to the peer's tree
//
// Encrypted GET requests decrypt the file using the peer's private key
//
// Encrypted PUT requests encrypt the file using the peer's public key in addition to the
// peerids in the "PEERIDS" header.
//
// Encrypted format uses a random 32-byte AES key encrypted by multiple public peer keys
// (including the encrypting peer):
//   (PLAINTEXT:)
//   [# keys: int32] -- do we really need to allow for more than 65535 peer keys?
//   [keylen: int16][key encrypted for peer 1]
//   [keylen: int16][key encrypted for peer 2]
//   ...
//   [initialization vector: AES BLOCK SIZE]
//   (CIPHERTEXT:)
//   [keylen: int16][peer id 1]
//   [keylen: int16][peer id 2]
//   ...
//   [content]
func PeerFileRequestHandler(prefix string, encrypted bool, published func(path string, treeCid cid.Cid)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID, treeName, file, err := PeerTreeFromURL(r.URL.Path[len(prefix):])
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		fmt.Printf("Peer ID: %s, tree: %s, file: %s", peerID.String(), treeName, file)
		if r.Method == http.MethodPut {
			func() error {
				var node ipld.Node

				if peerID != conf.host.ID() {return httpError(w, errstr("Attempt to write a file for a different peer"), http.StatusBadRequest)}
				t, err := GetTree(conf.host.ID(), treeName)
				if err == ds.ErrNotFound {
					node = unixfs.EmptyDirNode()
					tree := &CidTree{
						Nodes:     map[string]cid.Cid{"/": node.Cid()},
						FileNodes: []cid.Cid{node.Cid()},
					}
					svcSync(conf.conSvc, func() {
						conf.myTrees[treeName] = tree
					})
					err := tree.store(treeName, conf.host.ID())
					if err != nil {return httpError(w, errstrw("Could not store new tree", err), http.StatusBadRequest)}
				} else if err != nil {
					return httpError(w, errstrw("Could not fetch tree", err), http.StatusBadRequest)
				} else {
					block, err := conf.bstor.Get(t.Nodes["/"])
					if err != nil {return httpError(w, errstrw("Could not fetch block for tree", err), http.StatusBadRequest)}
					node, err = ipld.Decode(block)
					if err != nil {return httpError(w, errstrw("Could not decode block for tree", err), http.StatusBadRequest)}
				}
				root, err := storage.NewStorage(node.(*merkledag.ProtoNode), conf.dag)
				if err != nil {return httpError(w, errstrw("Could not create mfs root for tree", err), http.StatusBadRequest)}
				defer func() {
					root.Close()
				}()
				buf := bytes.NewBuffer(make([]byte, 0, 1024))
				_, err = buf.ReadFrom(r.Body)
				if err != nil {return httpError(w, errstrw("Could not read request body", err), http.StatusBadRequest)}
				content := buf.Bytes()
				if encrypted {
					keyStrs := r.Header.Values("Public-Keys")
					keys := make([]*x509.Certificate, len(keyStrs))
					var myCert *x509.Certificate
					for i, keyStr := range keyStrs {
						keyBytes, err := base58.Decode(keyStr)
						if err != nil {return httpError(w, errstrw("Could not decode key, %s: %w", keyStr, err), http.StatusBadRequest)}
						keys[i], err = x509.ParseCertificate(keyBytes)
						if err != nil {return httpError(w, errstrw("Could not decode key, %s: %w", keyStr, err), http.StatusBadRequest)}
						certKey, ok := keys[i].PublicKey.(*rsa.PublicKey)
						if !ok {return httpError(w, errstrw("Key is not an RSA key"), http.StatusBadRequest)}
						if equalPubKey(&conf.rsaKey.PublicKey, certKey) {
							myCert = keys[i]
						}
					}
					if myCert == nil {
						keys = append([]*x509.Certificate{conf.cert}, keys...)
					}
					content, err = Encrypt(buf.Bytes(), keys...)
					if err != nil {
						fmt.Println(err)
					}
					if err != nil {return httpError(w, errstrw("Could not encrypt data", err), http.StatusBadRequest)}
				}
				err2 := storage.StoreFile(root, file, content)
				if err2 != nil {return httpError(w, err2.ErrorStack(), http.StatusBadRequest)}
				node, err = root.GetDirectory().GetNode()
				if err != nil {return httpError(w, errstr("error getting stored directory %s", file), http.StatusBadRequest)}
				err = SetTree(treeName, node.Cid())
				if err != nil {return httpError(w, errstr("error publishing tree %s", file), http.StatusBadRequest)}
				fmt.Printf("###\n### New tree: %s\n###\n", node.Cid())
				err = Checkpoint()
				if err != nil {return httpError(w, errstr("error checkpointing tree %s", file), http.StatusBadRequest)}
				outputBytes, err := json.Marshal(node.Cid().String())
				if err != nil {return httpError(w, errstr("error encoding node cid %s", file), http.StatusBadRequest)}
				http.ServeContent(w, r, "output.json", time.Now(), bytes.NewReader(outputBytes))
				fmt.Println("PUBLISHING NEW ROOT")
				published(file, node.Cid())
				return nil
			}()
			return
		} else if r.Method != http.MethodGet {
			http.Error(w, errstr("Only GET and PUT are supported for "+prefix), http.StatusBadRequest)
			return
		}
		fmt.Println("Fetching tree")
		tree, err := FetchSync(peerID, treeName)
		if err != nil {
			http.Error(w, errstr(err.Error()), http.StatusNotFound)
			return
		}
		fmt.Printf("Tree: %v\n", tree)
		aCid := tree.Nodes[file]
		if aCid == cid.Undef {
			http.Error(w, errstr("No file %s for peer %s", file, peerID), http.StatusNotFound)
			return
		}
		fmt.Println("Fetching block for HTTP response:", aCid)
		ffile, fileTime, err := GetFile(r.URL.Path, aCid, encrypted)
		var errStr string
		switch err {
		case blockstore.ErrNotFound:
			errStr = errstr("Could not find file %s for peer %s", file, peerID)
		case errDecoding:
			errStr = errstrw("Could not decode file %s for peer %s", file, peerID, err)
		case errDecrypting:
			errStr = errstrw("Could decrypt file %s for peer %s", file, peerID, err)
		default:
			errStr = err.Error()
		case nil:
			http.ServeContent(w, r, file, fileTime, ffile)
			return
		}
		http.Error(w, errStr, http.StatusNotFound)
	}
}

//GetFile get a stream for a CID
func GetFile(name string, aCid cid.Cid, encrypted bool) (io.ReadSeeker, time.Time, error) {
	block, err := conf.bstor.Get(aCid)
	if err != nil {return nil, timeZero, blockstore.ErrNotFound}
	var ffile io.ReadSeeker
	ffile, err = storage.GetFileStreamForBlock(name, block, conf.dag)
	if err != nil {return nil, timeZero, errDecoding}
	if encrypted {
		content, _, err := Decrypt(ffile)
		if err != nil {
			fmt.Println(err.Error())
		}
		if err != nil {return nil, timeZero, errDecrypting}
		ffile = bytes.NewReader(content)
	}
	fileTime, err := TimeForBlock(block.Cid())
	if err != nil { // couldn't get time, so make it now
		fileTime = time.Now()
	}
	return ffile, fileTime, nil
}

//Encrypt encrypts content with multiple public keys output: [keylen][key][iv][ciphertext]
func Encrypt(content []byte, certs ...*x509.Certificate) ([]byte, error) {
	data, err := pkcs7.NewSignedData(content)
	if err != nil {return nil, withStack(err)}
	data.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	data.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)
	var signCert *x509.Certificate
	for _, cert := range certs {
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {return nil, withStack(fmt.Errorf("Certificate key is not an RSA key"))}
		if equalPubKey(&conf.rsaKey.PublicKey, pubKey) {
			signCert = cert
			break
		}
	}
	if signCert == nil {return nil, withStack(fmt.Errorf("No certificate for private key"))}
	err = data.AddSigner(signCert, conf.rsaKey, pkcs7.SignerInfoConfig{})
	if err != nil {return nil, withStack(err)}
	//data.Detach()
	signed, err := data.Finish()
	if err != nil {return nil, withStack(err)}
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	return pkcs7.Encrypt(signed, certs)
}

func equalPubKey(k1 *rsa.PublicKey, k2 *rsa.PublicKey) bool {
	return k1.N.Cmp(k2.N) == 0 && k1.E == k2.E
}

//Decrypt decrypt a file (eventually switch to CMS standard: http://pike.lysator.liu.se/docs/ietf/rfc/60/rfc6032.xml)
// input: [keylen][key][iv][ciphertext]
// output: plaintext, signer, error
func Decrypt(input io.ReadSeeker) ([]byte, peer.ID, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	_, err := buf.ReadFrom(input)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	p7, err := pkcs7.Parse(buf.Bytes())
	if err != nil {return nil, peer.ID(""), withStack(err)}
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	signedContent, err := p7.Decrypt(conf.cert, conf.rsaKey)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	p7, err = pkcs7.Parse(signedContent)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	err = p7.Verify()
	if err != nil {return nil, peer.ID(""), withStack(err)}
	pubKey, ok := p7.GetOnlySigner().PublicKey.(*rsa.PublicKey)
	if !ok {return nil, peer.ID(""), fmt.Errorf("public key is not an RSA key\n%s", stack(1))}
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	p2pPubKey, err := p2pcrypto.UnmarshalRsaPublicKey(keyBytes)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	id, err := peer.IDFromPublicKey(p2pPubKey)
	if err != nil {return nil, peer.ID(""), withStack(err)}
	return p7.Content, id, nil
}

func stack(level int) string {
	return strings.Join(strings.Split(string(debug.Stack()), "\n")[level+4:], "\n")
}

func errstr(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...) + "\n" + stack(2)
}

func errstrw(format string, args ...interface{}) string {
	return fmt.Sprintf(format+": %w", args...) + "\n" + stack(2)
}

func withStack(err error) error {
	return fmt.Errorf("%w\n%s", err, stack(2))
}

func httpError(w http.ResponseWriter, errMsg string, code int) error {
	http.Error(w, errMsg, code)
	return nil
}
