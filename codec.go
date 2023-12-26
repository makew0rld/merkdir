package main

import (
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/makew0rld/merkdir/merkle"
)

func writeTree(t *tree, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := cbor.NewEncoder(f)
	if err := enc.Encode(t); err != nil {
		return err
	}
	return nil
}

func readTree(path string) (*tree, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Get struct
	var t tree
	dec := cbor.NewDecoder(f)
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func writeInclusionProof(proof *merkle.InclusionProof, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := cbor.NewEncoder(f)
	if err := enc.Encode(proof); err != nil {
		return err
	}
	return nil
}

func readInclusionProof(path string) (*merkle.InclusionProof, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Get struct
	var proof merkle.InclusionProof
	dec := cbor.NewDecoder(f)
	if err := dec.Decode(&proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
