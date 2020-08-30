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

//Package storage convenience wrapper around mfs
package storage

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

//NewStorage create an mfs root to use for storage. Close it when you're done with it.
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
	filepath = path.Clean("/" + strings.Trim(filepath, "/"))
	parentName, childName := path.Split(filepath)
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
				if err != nil {return errors.New(fmt.Errorf("couldn't remove old directory entry for %v: %w", filepath, err))}
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

//GetFileStreamForBlock get a streem on the file for a block
func GetFileStreamForBlock(urlPath string, block blocks.Block, dag ipld.DAGService) (io.ReadSeeker, error) {
	node, err := ipld.Decode(block)
	if err != nil {return nil, fmt.Errorf("could not decode block: %w", err)}
	fsnode, err := unixfs.ExtractFSNode(node)
	if err != nil {return nil, fmt.Errorf("block is not an FSNode: %w", err)}
	if fsnode.IsDir() {
		urlPath = path.Clean("/" + urlPath)
		fmt.Println("Geting parent of", urlPath)
		parent := path.Dir(urlPath)
		builder := new(strings.Builder)
		builder.WriteString("<html><body>")
		if path.Dir(parent) != "/" {
			builder.WriteString(fmt.Sprintf("<a href='/peer%s'>[PARENT DIRECTORY]</a><br>", path.Dir(urlPath)))
		}
		for _, link := range node.Links() {
			builder.WriteString(fmt.Sprintf("<a href='/peer%s/%s'>%s</a><br>", urlPath, link.Name, link.Name))
		}
		builder.WriteString("</body></html>")
		return strings.NewReader(builder.String()), nil
	}
	fmt.Println("Links:")
	for _, link := range node.Links() {
		fmt.Printf("  %v\n", link.Cid)
	}
	n, err := ufile.NewUnixfsFile(context.Background(), dag, node)
	if err != nil {return nil, err}
	return files.ToFile(n), nil
}
