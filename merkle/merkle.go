// merkle handles creating Merkle trees.
// The method of creation is modeled after Certificate Transparency.
//
//	https://datatracker.ietf.org/doc/html/rfc9162#section-2.1
package merkle

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"lukechampine.com/blake3"
)

const (
	NonceSize  = 16 // 128 bits
	Blake3Size = 32 // 256 bits, like SHA2
)

type Nonce []byte

type Node struct {
	Hash  []byte
	Name  string `cbor:",omitempty"` // Filepath, used for leaf nodes
	Left  *Node  `cbor:",omitempty"` // Nil for leaves
	Right *Node  `cbor:",omitempty"` // Nil for leaves
	// Random nonce that was prepended to data before calculating hash
	// Only used for leaf nodes to anonymize actual file hash
	Nonce Nonce `cbor:",omitempty"`
}

func (n *Node) String() string {
	return fmt.Sprintf("Node{Name: %s, Hash: %x, Left: %+v, Right: %+v, Nonce: %v}", n.Name, n.Hash,
		n.Left, n.Right, n.Nonce)
}

type InclusionProof struct {
	LeafIndex uint64   // zero-indexed leaf number, from left to right
	TreeSize  uint64   // number of leaves
	Nonce     []byte   // Nonce for proven leaf
	Proof     [][]byte // Node hashes, in bottom-to-top order
}

// flp2 returns the previous power of 2 for the given integer.
func flp2(x uint64) uint64 {
	// https://stackoverflow.com/a/2681094
	x-- // Make result always less than x
	x = x | (x >> 1)
	x = x | (x >> 2)
	x = x | (x >> 4)
	x = x | (x >> 8)
	x = x | (x >> 16)
	x = x | (x >> 32)
	return x - (x >> 1)
}

func HashLeaf(r io.Reader, nonce Nonce) ([]byte, error) {
	hasher := blake3.New(Blake3Size, nil)
	hasher.Write([]byte{0x00})
	hasher.Write(nonce)
	_, err := io.Copy(hasher, r)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// CreateLeaf creates a leaf node.
// A random nonce is generated and used if the provided one is nil.
// The only possible errors are ones returned from the io.Reader, or those
// raised during random number generation.
func CreateLeaf(name string, r io.Reader, nonce Nonce) (*Node, error) {
	if nonce == nil {
		nonce = make(Nonce, NonceSize)
		_, err := rand.Read(nonce)
		if err != nil {
			return nil, err
		}
	}
	hash, err := HashLeaf(r, nonce)
	if err != nil {
		return nil, err
	}
	return &Node{
		Name:  name,
		Hash:  hash,
		Nonce: nonce,
	}, nil
}

// CreateTree create a Merkle tree from the given leaves.
// Leaves are used in the provided order. The root node of the newly-formed
// tree is returned.
func CreateTree(leaves []*Node) *Node {
	// Implementing this, minus creation of leaf nodes:
	// https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1

	if len(leaves) == 0 {
		// Return empty hash
		hash := blake3.Sum256([]byte{})
		return &Node{
			Hash: hash[:],
		}
	}
	if len(leaves) == 1 {
		// Nothing to combine this node with, promote it
		return leaves[0]
	}

	p2 := flp2(uint64(len(leaves)))
	left := CreateTree(leaves[:p2])
	right := CreateTree(leaves[p2:])

	hasher := blake3.New(Blake3Size, nil)
	hasher.Write([]byte{0x01})
	hasher.Write(left.Hash)
	hasher.Write(right.Hash)

	return &Node{
		Hash:  hasher.Sum(nil),
		Left:  left,
		Right: right,
	}
}

// GetInclusionProof returns a Merkle inclusion proof for the given tree and leaf.
//
// The leaf is indicated by an index argument, m. The first leaf in the tree is
// m=0, and so on. If the given leaf index doesn't exist, the function returns an error.
//
// The argument n is the total number of leaves in the tree. If that ends being
// incorrect, the function returns an error.
func GetInclusionProof(root *Node, n, m uint64) (*InclusionProof, error) {
	// Implementing this: https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.3.1

	if m >= n {
		return nil, errors.New("given leaf index is impossible")
	}
	if n == 1 {
		// Tree with single leaf, so a single node tree.
		// Proof is empty, as the single hash that is already known is all that is needed.
		return &InclusionProof{
			LeafIndex: m,
			TreeSize:  n,
			Nonce:     root.Nonce,
			Proof:     [][]byte{},
		}, nil
	}

	k := flp2(n)

	var path [][]byte
	var nonce []byte
	if m < k {
		if root.Right == nil {
			return nil, errors.New("given number of leaves is incorrect")
		}
		// The leaf we're looking for is on the left side. The left side tree has a
		// size of k, and the leaf we want remains at index m.
		ip, err := GetInclusionProof(root.Left, k, m)
		if err != nil {
			return nil, err
		}
		nonce = ip.Nonce
		path = append(ip.Proof, root.Right.Hash)
	} else {
		// m >= k

		if root.Left == nil {
			return nil, errors.New("given number of leaves is incorrect")
		}
		// The leaf we're looking for is on the right side. The right side tree has a
		// size of n-k, since the parent tree splits at k and n is the total size.
		// The leaf we want is at m-k, since we are subtracting all the leaves on the
		// left side (size k).
		ip, err := GetInclusionProof(root.Right, n-k, m-k)
		if err != nil {
			return nil, err
		}
		nonce = ip.Nonce
		path = append(ip.Proof, root.Left.Hash)
	}
	return &InclusionProof{
		LeafIndex: m,
		TreeSize:  n,
		Nonce:     nonce,
		Proof:     path,
	}, nil
}

// GetLeaf walks the given tree and returns the requested leaf.
// It works similarly to GetInclusionProof, and returns errors in the same way.
func GetLeaf(root *Node, n, m uint64) (*Node, error) {
	// Adapted from GetInclusionProof implementation

	if m >= n {
		return nil, errors.New("given leaf index is impossible")
	}
	if n == 1 {
		// Tree with single leaf, so a single node tree.
		return root, nil
	}
	k := flp2(n)
	if m < k {
		if root.Right == nil {
			return nil, errors.New("given number of leaves is incorrect")
		}
		return GetLeaf(root.Left, k, m)
	} else {
		// m >= k

		if root.Left == nil {
			return nil, errors.New("given number of leaves is incorrect")
		}
		return GetLeaf(root.Right, n-k, m-k)
	}
}

// CalcInclusion proof gets the root hash for the given inclusion proof.
//
// The proof argument is the result of GetInclusionProof.
//
// An error is not returned if the inclusion proof was not verified.
//
// Note the inclusion proof may or may not be valid, it depends on what root hash
// you are expecting. The root hash must be verified outside of this function.
func CalcInclusionProof(proof *InclusionProof, reader io.Reader) ([]byte, error) {
	leafHash, err := HashLeaf(reader, proof.Nonce)
	if err != nil {
		return nil, err
	}

	// Implementing: https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.3.2

	if proof.LeafIndex >= proof.TreeSize {
		return nil, errors.New("invalid leaf index")
	}
	fn := proof.LeafIndex
	sn := proof.TreeSize - 1
	r := leafHash
	for _, p := range proof.Proof {
		if sn == 0 {
			return nil, errors.New("tree size and leaf index mismatch")
		}
		if fn&0x1 == 1 || fn == sn {
			hasher := blake3.New(Blake3Size, nil)
			hasher.Write([]byte{0x01})
			hasher.Write(p)
			hasher.Write(r)
			r = hasher.Sum(nil)
			for fn&0x1 == 0 && fn != 0 {
				// Right-shift until LSB(fn) is set, or fn is 0
				fn >>= 1
				sn >>= 1
			}
		} else {
			hasher := blake3.New(Blake3Size, nil)
			hasher.Write([]byte{0x01})
			hasher.Write(r)
			hasher.Write(p)
			r = hasher.Sum(nil)
		}

		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return nil, errors.New("tree size and leaf index mismatch")
	}
	return r, nil
}
