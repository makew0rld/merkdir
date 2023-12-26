package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/makew0rld/merkdir/merkle"
)

// tree holds extra Merkle tree information used for serialization.
type tree struct {
	Path      string            // Original absolute filesystem path
	Files     map[string]uint64 // Map relative filepaths to leaf numbers. Also len(files) = tree size.
	CreatedAt time.Time
	Root      *merkle.Node
}

func genInclusionProof(t *tree, name string) (*merkle.InclusionProof, error) {
	leafN, ok := t.Files[name]
	if !ok {
		return nil, errors.New("filename not found in tree")
	}
	treeSize := uint64(len(t.Files))
	ip, err := merkle.GetInclusionProof(t.Root, treeSize, leafN)
	if err != nil {
		return nil, fmt.Errorf("error calculating proof: %w", err)
	}
	return ip, nil
}
