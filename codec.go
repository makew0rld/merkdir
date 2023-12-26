package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/makew0rld/merkdir/merkle"
)

const (
	// Version written to disk. 0 version is reserved as an error.
	fileVersion = 0x1
)

var (
	fileMagicNumber = []byte("merkdir")
	fileHeader      = append(fileMagicNumber, fileVersion)
)

func writeTree(t *tree, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	// Write header
	if _, err = f.Write(fileHeader); err != nil {
		return err
	}
	// Write tree
	//enc := gob.NewEncoder(f)
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
	// Confirm file type and version
	header := make([]byte, len(fileHeader))
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header, fileHeader) {
		return nil, fmt.Errorf("invalid file header")
	}
	// Get struct
	var t tree
	//dec := gob.NewDecoder(f)
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
	// Write header
	if _, err = f.Write(fileHeader); err != nil {
		return err
	}
	// Write proof
	//enc := gob.NewEncoder(f)
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
	// Confirm file type and version
	header := make([]byte, len(fileHeader))
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header, fileHeader) {
		return nil, fmt.Errorf("invalid file header")
	}
	// Get struct
	var proof merkle.InclusionProof
	//dec := gob.NewDecoder(f)
	dec := cbor.NewDecoder(f)
	if err := dec.Decode(&proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
