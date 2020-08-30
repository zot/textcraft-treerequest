# Treerequest, a libp2p protocol implementation for requesting trees directly from other peers
A block request protocol for ipfs

Each peer can provide a set of persistent root nodes and their children.

Other peers can ask for the CIDs of the trees and also any of the blocks.

Access can be restricted to a set of peers.

Known tree CIDs are stored in the data store you provide.

For convenience, there are http services to access the trees given a prefix you provide that
handle GET and (for your own peer) PUT requests with optional encryption for a provided URL prefix:

```
  unencrypted access: /PREFIX/PEERID/PATH
  encrypted access (only for your peer's files): /PREFIX/PATH
```

Before using the package, you must call InitTreeRequest().

IPFS-lite works well with TreeRequest and provides all of the required values for InitTreeRequest():

```
  ipfslite.BadgerDatastore(PATH) returns a ds.Datastore
  (*ipfslite.Peer).BlockStore() returns a blockstore.Blockstore
  *ipfslite.Peer implements ipld.DAGService
  (*ipfslite.Peer).Session(CTX) returns an ipld.NodeGetter
```
