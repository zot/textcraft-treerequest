package treerequest

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/go-errors/errors"
	blocks "github.com/ipfs/go-block-format"
	files "github.com/ipfs/go-ipfs-files"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-mfs"
	"github.com/ipfs/go-unixfs"
	ufile "github.com/ipfs/go-unixfs/file"
	pb "github.com/ipfs/go-unixfs/pb"
)

//NewStorage initialize storage library
func NewStorage(protoNode *merkledag.ProtoNode, ds ipld.DAGService) (root *mfs.Root, err error) {
	root, err = mfs.NewRoot(context.Background(), ds, protoNode, nil)
	if err != nil {return nil, errors.New(err)}
	return
}

//GetRoot gets the current root node
func GetRoot(root *mfs.Root) (ipld.Node, error) {
	return root.GetDirectory().GetNode()
}

//StoreFile store a file
func StoreFile(root *mfs.Root, filepath string, contents []byte) *errors.Error {
	parentName, childName := path.Split(path.Clean("/" + strings.Trim(filepath, "/")))
	fmt.Printf("parent: %s, child: %s\n", parentName, childName)
	err := mfs.Mkdir(root, parentName, mfs.MkdirOpts{Mkparents: true, Flush: true, CidBuilder: root.GetDirectory().GetCidBuilder()})
	if err != nil {return errors.New(err)}
	file := unixfs.NewFSNode(pb.Data_File)
	file.SetData(contents)
	bytes, err := file.GetBytes()
	if err != nil {return errors.New(err)}
	dirNode, err := mfs.Lookup(root, parentName)
	if err == nil {
		fmt.Printf("preparing to remove old file %s/%s\n", parentName, childName)
		dir, ok := dirNode.(*mfs.Directory)
		if ok {
			if _, err = dir.Child(childName); err == nil {
				fmt.Printf("removing old file %s/%s\n", parentName, childName)
				err = dir.Unlink(childName)
				if err != nil {return errors.New(fmt.Errorf("Couldn't remove old directory entry for %v: %w", filepath, err))}
			}
		} else {
			return errors.New("parent is not a directory")
		}
	} else {
		fmt.Printf("file is new: %s/%s\n", parentName, childName)
	}
	err = mfs.PutNode(root, filepath, merkledag.NodeWithData(bytes))
	if err != nil {return errors.New(err)}
	err = root.Flush()
	if err != nil {return errors.New(err)}
	return nil
}

//GetFSNode get the node at a path
func GetFSNode(root *mfs.Root, path string) (mfs.FSNode, error) {
	return mfs.Lookup(root, path)
}

//GetNodeForFSNode convert an FSNode to a DAG node
func GetNodeForFSNode(fsnode mfs.FSNode) (*merkledag.ProtoNode, error) {
	inode, err := fsnode.GetNode()
	if err != nil {return nil, errors.New(err)}
	mnode, ok := inode.(*merkledag.ProtoNode)
	if !ok {return nil, errors.New("node is not a protonode")}
	return mnode, nil
}

//GetNode get the DAG node at a path
func GetNode(root *mfs.Root, path string) (*merkledag.ProtoNode, error) {
	fsnode, err := GetFSNode(root, path)
	if err != nil {return nil, errors.New(err)}
	return GetNodeForFSNode(fsnode)
}

//GetFile get data for file at path
func GetFile(root *mfs.Root, path string) ([]byte, error) {
	mnode, err := GetNode(root, path)
	if err != nil {return nil, err}
	return mnode.Data(), nil
}

func getFileForBlock(urlPath string, block blocks.Block) (io.ReadSeeker, error) {
	node, err := ipld.Decode(block)
	if err != nil {return nil, fmt.Errorf("could not decode block: %w", err)}
	fsnode, err := unixfs.ExtractFSNode(node)
	if err != nil {return nil, fmt.Errorf("block is not an FSNode: %w", err)}
	if fsnode.IsDir() {
		urlPath = path.Clean("/" + urlPath)
		fmt.Println("Geting parent of", urlPath)
		parent := path.Dir(urlPath)
		builder := new(strings.Builder)
		if path.Dir(parent) != "/" {
			builder.WriteString(fmt.Sprintf("<a href='/peer%s'>[PARENT DIRECTORY]</a><br>", path.Dir(urlPath)))
		}
		for _, link := range node.Links() {
			builder.WriteString(fmt.Sprintf("<a href='/peer%s/%s'>%s</a><br>", urlPath, link.Name, link.Name))
		}
		return strings.NewReader(builder.String()), nil
	}
	fmt.Println("Links:")
	for _, link := range node.Links() {
		fmt.Printf("  %v\n", link.Cid)
	}
	n, err := ufile.NewUnixfsFile(context.Background(), conf.dag, node)
	if err != nil {return nil, err}
	return files.ToFile(n), nil
}
