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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	pinner "github.com/ipfs/go-ipfs-pinner"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-unixfs"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	msgpack "github.com/vmihailenco/msgpack/v5"

	packet "github.com/zot/textcraft-packet"
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

//message a blockRequest message
type message interface {
	getMessageType() blockRequestMessageType
	getID() uint64
	// process is called in its own goroutine
	process(con *connection) error
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
	peerKey            crypto.PrivKey
	connectionCallback func(peer.ID)
	lastRefresh        map[peer.ID]time.Time
	pin                pinner.Pinner
	announced          map[cid.Cid]bool
}

type msgRequest interface {
	supportsRequest()
}
type msgBase struct {
	id uint64
}
type msgRequestTree struct {
	msgBase
	tree string
}
type msgRequestContents struct {
	msgBase
	nodeCids [][]byte
	tree     string
}
type msgResponseTree struct {
	msgBase
	CidTree
}
type msgResponseContents struct {
	msgBase
	contents [][]byte
	missing  [][]byte
}
type msgError struct {
	msgBase
	msg string
}

//RequestResult result for an asynchronous request
type RequestResult struct {
	Err  error
	Tree *CidTree
}

var pendingTrees = make(map[peer.ID][]chan RequestResult)

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
func (msg msgBase) getMessageType() blockRequestMessageType { return -1 }
func (msg msgBase) getID() uint64                           { return msg.id }
func (msg msgBase) process(con *connection) error {
	result := make(chan error)
	svcAsync(con.svc, func() {
		reqChan := con.openRequests[msg.getID()]
		if reqChan == nil {
			result <- fmt.Errorf("response for missing message id: %d", msg.getID())
		} else {
			delete(con.openRequests, msg.getID())
			reqChan <- message(msg)
			result <- nil
		}
	})
	return <-result
}
func (msg msgRequestTree) getMessageType() blockRequestMessageType { return reqCID }
func (msg msgRequestTree) supportsRequest()                        {}
func (msg msgRequestTree) process(con *connection) (err error) {
	var tree *CidTree
	if tree, err = con.getTree(msg.id, msg.tree); err != nil {return}
	return con.write(&msgResponseTree{
		msgBase{msg.id},
		*tree,
	})
}
func (msg msgRequestContents) getMessageType() blockRequestMessageType { return reqContents }
func (msg msgRequestContents) supportsRequest()                        {}
func (msg msgRequestContents) process(con *connection) (err error) {
	var aCid cid.Cid
	var tree *CidTree
	contents := make([][]byte, 0, len(msg.nodeCids))
	missing := make([][]byte, 0, len(msg.nodeCids))
	if tree, err = con.getTree(msg.id, msg.tree); err != nil {return}
	allCids := tree.AllCids()
	for _, bytes := range msg.nodeCids {
		aCid, err = cid.Cast(bytes)
		if err != nil {return fmt.Errorf("error decoding requested CID in msg %d: %w", msg.id, err)}
		if allCids[aCid] {
			blk, err := conf.bstor.Get(aCid)
			if err != nil {return err}
			contents = append(contents, blk.RawData())
		} else {
			missing = append(missing, bytes)
		}
	}
	err = con.write(&msgResponseContents{
		msgBase{msg.id},
		contents,
		missing,
	})
	return
}
func (msg msgResponseTree) getMessageType() blockRequestMessageType     { return respCID }
func (msg msgResponseContents) getMessageType() blockRequestMessageType { return respContents }
func (msg msgError) getMessageType() blockRequestMessageType            { return respError }
func (msg msgError) Error() string                                      { return msg.msg }

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
func InitTreeRequest(protocolName string, dstor ds.Datastore, inputHost host.Host, peerKey crypto.PrivKey, bstor blockstore.Blockstore, getter ipld.NodeGetter, dagService ipld.DAGService, pin pinner.Pinner, cacheSize int, trees map[string]cid.Cid, newConnection func(peer.ID)) error {
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
	conf.peerKey = peerKey
	conf.connectionCallback = newConnection
	conf.pin = pin
	conf.announced = make(map[cid.Cid]bool)
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
	err := findRefs()
	if err != nil {return err}
	conf.host.SetStreamHandler(conf.protocol, func(stream network.Stream) {
		if conf.peers[stream.Conn().RemotePeer()] {
			runProtocol(stream, true)
		} else {
			// terminate connections from the uninvited
			err := stream.Close()
			if err != nil {
				fmt.Printf("Error closing uninvited stream: %v\n", err)
			}
		}
	})
	return nil
}

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
		refreshTree(treeName, peerID)
	}
	for _, peer := range remove {
		delete(conf.peers, peer)
	}
}

func refreshTree(treeName string, peerID peer.ID) {
	if shouldRefresh(peerID) {
		var treeCid cid.Cid
		cur, err := GetTree(treeName, peerID)
		if err == nil {
			treeCid = cur.Root()
		}
		requestTree(treeName, peerID, treeCid)
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

//only run this inside con's svc goroutine
func (con connection) newRequest() (msgBase, chan message) {
	con.requestID++
	id := con.requestID
	response := make(chan message)
	con.openRequests[id] = response
	return msgBase{id}, response
}

//FetchSync synchronously get the latest tree from a peer
func FetchSync(name string, peerID peer.ID, more bool) (*CidTree, chan *CidTree, error) {
	results := Fetch(name, peerID)
	result := <-results
	var next chan *CidTree
	if result.Err == nil && more {
		next := make(chan *CidTree)
		go func() {
			result, ok := <-results
			if ok && result.Err == nil {
				next <- result.Tree
			}
			close(next)
		}()
	}
	return result.Tree, next, result.Err
}

//Fetch get the latest tree from a peer
func Fetch(name string, peerID peer.ID) (done chan RequestResult) {
	done = make(chan RequestResult, 1) // non-blocking
	fmt.Println("###\n### CHECKING FOR PENDING REQUESTS\n###")
	var myTree *CidTree
	svcSync(conf.conSvc, func() {
		if peerID == conf.host.ID() {
			myTree = conf.myTrees[name]
		}
		if pendingTrees[peerID] != nil { // already a pending request, get in line!
			pendingTrees[peerID] = append(pendingTrees[peerID], done)
			fmt.Println("###\n### ALREADY PENDING, QUEUING REQUEST\n###")
			return
		}
	})
	if peerID == conf.host.ID() {
		if myTree == nil {
			done <- RequestResult{fmt.Errorf("no tree named %s", name), nil}
		} else {
			done <- RequestResult{nil, myTree}
		}
		return
	}
	fmt.Println("###\n### CHECKING FOR TREE\n###")
	tree, err := GetTree(name, peerID) // check if we already have a tree
	fmt.Println("###\n### GOT TREE: %v\n###", tree)
	if err != nil {
		fmt.Printf("###\n### ERROR GETTING TREE: %v\n###\n", err)
	}
	if err != nil && (peerID == conf.host.ID() || err != ds.ErrNotFound) {
		done <- RequestResult{err, nil}
	} else {
		knownRoot := cid.Undef
		svcSync(conf.conSvc, func() {
			pendingTrees[peerID] = make([]chan RequestResult, 0, 8)
		})
		if err == nil { // already have the tree
			done <- RequestResult{err, tree}
			knownRoot = tree.Root()
			if peerID == conf.host.ID() || !shouldRefresh(peerID) {return}
		} else if peerID == conf.host.ID() {
			done <- RequestResult{fmt.Errorf("peer does not have tree %s", name), nil}
			return done
		} else { // not found in storage
			svcSync(conf.conSvc, func() {
				pendingTrees[peerID] = append(pendingTrees[peerID], done)
			})
		}
		requestTree(name, peerID, knownRoot)
	}
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
func requestTree(name string, peerID peer.ID, knownRoot cid.Cid) {
	svcSync(conf.conSvc, func() {
		conf.lastRefresh[peerID] = time.Now()
	})
	go func() {
		var tree *CidTree
		stream, err := conf.host.NewStream(context.Background(), peerID, conf.protocol)
		if err == nil {
			con := runProtocol(stream, false)
			base, result := con.newRequest()
			err = con.write(&msgRequestTree{base, name})
			if err == nil {
				resp := <-result
				if msg, ok := resp.(msgResponseTree); ok {
					tree = &msg.CidTree
				} else if errMsg, ok := resp.(msgError); ok {
					err = errMsg
				} else {
					err = fmt.Errorf("unexpected response: %v", msg)
				}
				if err == nil && knownRoot != tree.Root() { // fetch new blocks
					fetching, err := con.fetchUnknownBlocks(name, tree)
					if err == nil && fetching {return}
				}
			}
		}
		finished(name, peerID, tree, tree != nil && knownRoot != tree.Root(), err)
	}()
}

func finished(name string, peerID peer.ID, tree *CidTree, store bool, err error) {
	if err != nil {
		tree = nil
	}
	result := RequestResult{err, tree}
	svcAsync(conf.conSvc, func() {
		if err == nil && store { // make sure the tree is stored before sending result
			err = tree.store(name, peerID)
		}
		chans := pendingTrees[peerID]
		if chans != nil {
			for _, channel := range chans {
				channel <- result
			}
			delete(pendingTrees, peerID)
		}
	})
}
func checkBlockFetch(aCid cid.Cid, fetch [][]byte) ([][]byte, error) {
	has, err := conf.bstor.Has(aCid)
	if err != nil {return nil, err}
	if !has {return append(fetch, aCid.Bytes()), nil}
	return fetch, nil
}

func (con connection) fetchUnknownBlocks(name string, tree *CidTree) (bool, error) {
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
		var base msgBase
		var result chan message
		con.svcSync(func() {
			base, result = con.newRequest()
		})
		err = con.write(&msgRequestContents{base, fetch, name})
		if err != nil {return false, err}
		go func() {
			resp := <-result
			if msg, ok := resp.(msgResponseContents); ok {
				now := time.Now()
				var nowBytes [8]byte
				binary.BigEndian.PutUint64(nowBytes[:], uint64(now.Unix()))
				for _, item := range msg.contents { // store the blocks
					block := blocks.NewBlock(item)
					err = conf.bstor.Put(block)
					if err != nil {
						finished(name, con.stream.Conn().RemotePeer(), nil, false, err)
						return
					}
					err := conf.dstor.Put(timeKey(block.Cid()), nowBytes[:])
					if err != nil {
						finished(name, con.stream.Conn().RemotePeer(), nil, false, err)
						return
					}
				}
				finished(name, con.stream.Conn().RemotePeer(), tree, true, nil)
			} else if _, ok := resp.(msgError); ok {
				finished(name, con.stream.Conn().RemotePeer(), nil, false, err)
			} else {
				finished(name, con.stream.Conn().RemotePeer(), nil, false, fmt.Errorf("unexpected response: %v", msg))
			}
		}()
		return true, nil
	}
	return false, nil
}

func timeKey(aCid cid.Cid) ds.Key {
	return ds.NewKey("time-" + aCid.KeyString())
}

//TimeForBlock get the time a block was stored
func TimeForBlock(blockCid cid.Cid) (time.Time, error) {
	timeBytes, err := conf.dstor.Get(timeKey(blockCid))
	if err != nil {return time.Unix(0, 0), err}
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
func GetTree(name string, peerID peer.ID) (*CidTree, error) {
	var tree CidTree
	bytes, err := conf.dstor.Get(keyForPeer("tree", name, peerID))
	if err != nil {return nil, err}
	err = msgpack.Unmarshal(bytes, &tree)
	if err != nil {return nil, err}
	return &tree, nil
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

func getTree(name string, peerID peer.ID) (*CidTree, error) {
	var tree CidTree
	treeBytes, err := conf.dstor.Get(keyForPeer("tree", name, peerID))
	if err == ds.ErrNotFound {return nil, nil}
	if err != nil {return nil, err}
	err = msgpack.Unmarshal(treeBytes, &tree)
	return &tree, err
}

func (tree CidTree) changeRefs(name string, peerID peer.ID) error {
	oldTree, err := getTree(name, peerID)
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
		for err == nil { // process packets until an error
			err = con.readPacket(req)
			if err != nil && err != io.EOF {
				con.streamError(0, err)
			}
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

func (con connection) readPacket(req chan message) (err error) {
	var msgType uint8
	var msg message
	msgType, err = con.decoder.DecodeUint8()
	if err == nil {
		msg, err = newMessage(blockRequestMessageType(msgType))
		if err == nil {
			_, err = packet.Decode(con.decoder, msg)
			req <- msg.(message)
		}
	}
	return
}

func (con connection) processPackets() (messageChan chan message) {
	messageChan = make(chan message)
	go func() {
		for code := range con.svc {
			code()
		}
	}()
	go func() {
		for req := range messageChan {
			var err error
			_, isRequest := req.(msgRequest)
			if !con.serve && isRequest {
				err = fmt.Errorf("received request on a non-serving connection %v", req)
			} else {
				err = req.process(&con)
			}
			if err != nil {
				if err != io.EOF {
					con.streamError(req.getID(), err)
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
	err = con.stream.SetWriteDeadline(time.Unix(0, 0))
	if err == nil {
		buf, err = packet.Marshal(msg)
	}
	if err == nil {
		_, err = bytes.NewBuffer(buf).WriteTo(con.stream)
	}
	return
}

func (con connection) getTree(id uint64, name string) (*CidTree, error) {
	if conf.myTrees[name] == nil {return nil, con.streamError(id, fmt.Errorf("no tree named %s", name))}
	return conf.myTrees[name], nil
}

func (con connection) streamError(id uint64, err error) error {
	err = con.write(&msgError{msgBase{id}, err.Error()})
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

//PeerFileRequestHandler returns a handler for tree requests
func PeerFileRequestHandler(prefix string, encrypted bool, published func(path string, treeCid cid.Cid)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var peerID peer.ID
		var err error
		var pind int
		urlPath := r.URL.Path[len(prefix):]
		if encrypted {
			peerID = conf.host.ID()
			pind = -1
		} else {
			pind = strings.Index(urlPath, "/")
			peerID, err = peer.Decode(urlPath[0:pind])
			if err != nil {
				http.Error(w, errstr("Bad peer id: %s", urlPath[0:pind]), http.StatusNotFound)
				return
			}
		}
		nind := pind + 1 + strings.Index(urlPath[pind+1:], "/")
		if nind <= pind {
			nind = len(urlPath)
		}
		treeName := urlPath[pind+1 : nind]
		file := path.Clean("/" + urlPath[nind:])
		fmt.Printf("Peer ID: %s, tree: %s, file: %s", peerID.String(), treeName, file)
		if r.Method == http.MethodPut {
			func() error {
				var node ipld.Node

				if peerID != conf.host.ID() {return httpError(w, errstr("Attempt to write a file for a different peer"), http.StatusBadRequest)}
				t, err := GetTree(treeName, conf.host.ID())
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
					content, err = encrypt(buf.Bytes())
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
		tree, _, err := FetchSync(treeName, peerID, false)
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
		block, err := conf.bstor.Get(aCid)
		if err != nil {
			http.Error(w, errstr("Could not find file %s for peer %s", file, peerID), http.StatusNotFound)
			return
		}
		var ffile io.ReadSeeker
		ffile, err = storage.GetFileStreamForBlock(urlPath, block, conf.dag)
		if err != nil {
			http.Error(w, errstrw("Could not decode file %s for peer %s", file, peerID, err), http.StatusNotFound)
			return
		}
		if encrypted {
			ffile, err = decryptedStream(ffile)
			if err != nil {
				http.Error(w, errstrw("Could decrypt file %s for peer %s", file, peerID, err), http.StatusNotFound)
				return
			}
		}
		fileTime, err := TimeForBlock(block.Cid())
		if err != nil { // couldn't get time, so make it long, long ago
			fileTime = time.Unix(0, 0)
		}
		http.ServeContent(w, r, file, fileTime, ffile)
	}
}

// output: [keylen][key][iv][ciphertext]
func encrypt(content []byte) ([]byte, error) {
	rsaKey, err := getRsaKey()
	if err != nil {return nil, err}
	aesKey := make([]byte, 32)
	_, err = rand.Read(aesKey)
	if err != nil {return nil, err}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, aesKey, []byte("file"))
	if err != nil {return nil, err}
	output := bytes.NewBuffer([]byte{})
	binary.Write(output, binary.BigEndian, uint32(len(ciphertext))) // size of encrypted key
	_, err = output.Write(ciphertext)                               // encrypted key
	if err != nil {return nil, err}
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {return nil, err}
	iv := make([]byte, blockCipher.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {return nil, err}
	output.Write(iv)
	dst := make([]byte, len(content))
	cipher.NewCTR(blockCipher, iv).XORKeyStream(dst, content)
	_, err = output.Write(dst)
	if err != nil {return nil, err}
	return output.Bytes(), nil
}

// input: [keylen][key][iv][ciphertext]
func decryptedStream(input io.ReadSeeker) (io.ReadSeeker, error) {
	rsaKey, err := getRsaKey()
	if err != nil {return nil, err}
	buf := bytes.NewBuffer(make([]byte, 0, 16))
	_, err = buf.ReadFrom(input)
	if err != nil {return nil, err}
	var keyLen int32
	err = binary.Read(buf, binary.BigEndian, &keyLen)
	if err != nil {return nil, err}
	encryptedKey := buf.Next(int(keyLen))
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encryptedKey, []byte("file"))
	if err != nil {return nil, err}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {return nil, err}
	iv := buf.Next(blockCipher.BlockSize())
	plaintext := make([]byte, buf.Len())
	cipher.NewCTR(blockCipher, iv).XORKeyStream(plaintext, buf.Bytes())
	return bytes.NewReader(plaintext), nil
}

// get key, which should be an RSA key
func getRsaKey() (*rsa.PrivateKey, error) {
	key, err := crypto.PrivKeyToStdKey(conf.peerKey)
	if err != nil {return nil, err}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {return nil, fmt.Errorf("peer key is not an RSA key")}
	fmt.Printf("KEY SIZE: %d\n", rsaKey.PublicKey.Size())
	return rsaKey, nil
}

func errstr(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...) + "\n" + strings.Join(strings.Split(string(debug.Stack()[2:]), "\n")[5:], "\n")
}

func errstrw(format string, args ...interface{}) string {
	return errstr(format+": %w", args...)
}

func httpError(w http.ResponseWriter, errMsg string, code int) error {
	http.Error(w, errMsg, code)
	return nil
}
