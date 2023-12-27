package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/makew0rld/merkdir/merkle"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
)

// pbReader updates the progress bar for each read
type pbReader struct {
	bar *progressbar.ProgressBar
	r   io.Reader
}

func (pbr *pbReader) Read(p []byte) (n int, err error) {
	n, err = pbr.r.Read(p)
	if err == nil {
		err = pbr.bar.Add(n)
	}
	return
}

func gen(ctx *cli.Context) error {
	dirPath := ctx.Args().First()

	leaves := make([]*merkle.Node, 0)
	files := make(map[string]uint64, 0)
	dirFS := os.DirFS(dirPath)
	startTime := time.Now().UTC()

	fmt.Println("Finding files...")
	filePaths := make([]string, 0)
	var totalSize int64
	err := fs.WalkDir(dirFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type() != 0 {
			// Some sort of special file
			fmt.Printf("Ignoring special file: %s\n", path)
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		totalSize += fi.Size()
		filePaths = append(filePaths, path)
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d files. Starting hashing...\n", len(filePaths))
	bar := progressbar.DefaultBytes(totalSize, "")

	// Have a number of workers go through the files and hash them
	var wg sync.WaitGroup
	errCh := make(chan error)
	leafCh := make(chan *merkle.Node)
	pathCh := make(chan string)
	// 2*numCPU workers is just a handpicked number.
	// It seems to work better than just # of CPUs since this is more I/O-bound
	// than CPU-bound since blake3 is so fast.
	for i := 0; i < runtime.NumCPU()*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for path := range pathCh {
				f, err := os.Open(filepath.Join(dirPath, path))
				if err != nil {
					errCh <- err
					return
				}
				defer f.Close()
				leaf, err := merkle.CreateLeaf(path, &pbReader{bar, f}, nil)
				if err != nil {
					errCh <- err
					return
				}
				leafCh <- leaf
			}
		}()
	}
	// Assign work
	go func() {
		for _, path := range filePaths {
			pathCh <- path
		}
		close(pathCh)
	}()
	// Signal when all are done with no errors
	go func() {
		wg.Wait()
		errCh <- nil
	}()

outer:
	for {
		select {
		case err := <-errCh:
			if err == nil {
				// All workers done without errors
				break outer
			} else {
				return err
			}
		case leaf := <-leafCh:
			// Add leaf to pre-tree
			files[leaf.Name] = uint64(len(leaves))
			leaves = append(leaves, leaf)
		}
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return err
	}
	merkTree := tree{
		Path:      absPath,
		Files:     files,
		Root:      merkle.CreateTree(leaves),
		CreatedAt: startTime,
	}
	fmt.Printf("Root hash: %x\n", merkTree.Root.Hash)

	return writeTree(&merkTree, ctx.String("output"))
}

func root(ctx *cli.Context) error {
	t, err := readTree(ctx.Args().First())
	if err != nil {
		return fmt.Errorf("error reading or decoding file: %w", err)
	}
	if ctx.Bool("hex") {
		fmt.Printf("%x\n", t.Root.Hash)
	} else {
		os.Stdout.Write(t.Root.Hash)
	}
	return nil
}

func inclusion(ctx *cli.Context) error {
	t, err := readTree(ctx.String("tree"))
	if err != nil {
		return fmt.Errorf("error reading or decoding file: %w", err)
	}

	proof, err := genInclusionProof(t, ctx.String("file"))
	if err != nil {
		return err
	}
	if len(ctx.String("output")) > 0 {
		return writeInclusionProof(proof, ctx.String("output"))
	}
	// Text version of inclusion proof
	// fmt.Println("== Text explanation of inclusion proof ==")
	// fmt.Printf("Tree size: %d\n", len(t.Files))
	// fmt.Printf("Provided file (%s) corresponds to leaf index %d\n", ctx.String("file"), proof.LeafIndex)
	// fmt.Printf("Tree root hash: %x\n", t.Root.Hash)
	// fmt.Printf("File nonce: %x\n", proof.Nonce)
	// fmt.Println("Operations to calculate that root hash:")
	// fmt.Println("digest = hash(0x00 || nonce || file data)")
	fmt.Println("Text explanation of inclusion proof is not implemented.",
		"Use --output/-o to store the binary proof instead.")
	return nil
}

func verifyFile(ctx *cli.Context) error {
	// This function assumes the stored tree is valid.
	// So it only checks that the file hash matches the one stored in the tree
	// (plus nonce etc.), not that the hash can be traced back to the root.

	t, err := readTree(ctx.String("tree"))
	if err != nil {
		return fmt.Errorf("error reading or decoding file: %w", err)
	}
	name := ctx.String("name")
	leafN, ok := t.Files[name]
	if !ok {
		return fmt.Errorf("file with that name not found in Merkle tree")
	}
	leaf, err := merkle.GetLeaf(t.Root, uint64(len(t.Files)), leafN)
	if err != nil {
		return fmt.Errorf("error finding leaf in tree: %w", err)
	}
	f, err := os.Open(filepath.Join(t.Path, name))
	if err != nil {
		return err
	}
	defer f.Close()
	hash, err := merkle.HashLeaf(f, leaf.Nonce)
	if err != nil {
		return err
	}
	if bytes.Equal(hash, leaf.Hash) {
		fmt.Println("OK: file is still verified by this Merkle tree")
		return nil
	}
	fmt.Println("NOT OK: file has changed and is not part of the Merkle tree")
	return nil
}

func verifyInclusion(ctx *cli.Context) error {
	ip, err := readInclusionProof(ctx.String("proof"))
	if err != nil {
		return fmt.Errorf("error reading or decoding file: %w", err)
	}
	f, err := os.Open(ctx.String("file"))
	if err != nil {
		return err
	}
	defer f.Close()
	rootHash, err := merkle.CalcInclusionProof(ip, f)
	if err != nil {
		return fmt.Errorf("unexpected verification failure: %w", err)
	}

	if len(ctx.String("hash")) > 0 {
		givenRootHash, err := hex.DecodeString(ctx.String("hash"))
		if err != nil {
			return fmt.Errorf("failed to decode given hexadecimal hash: %w", err)
		}
		if bytes.Equal(givenRootHash, rootHash) {
			fmt.Println("OK: proof and file match given root hash")
			return nil
		}
		fmt.Println("NOT OK: proof and file don't match given root hash")
		return nil
	}
	if ctx.Bool("hex") {
		fmt.Printf("%x\n", rootHash)
	} else {
		os.Stdout.Write(rootHash)
	}
	return nil
}

func info(ctx *cli.Context) error {
	t, err := readTree(ctx.Args().First())
	if err != nil {
		return fmt.Errorf("error reading or decoding file: %w", err)
	}

	if len(ctx.String("proof")) > 0 {
		// Info for inclusion proof
		ip, err := readInclusionProof(ctx.String("proof"))
		if err != nil {
			return fmt.Errorf("error reading or decoding file: %w", err)
		}
		leaf, err := merkle.GetLeaf(t.Root, ip.TreeSize, ip.LeafIndex)
		if err != nil {
			return fmt.Errorf("error finding leaf from inclusion proof in tree: %w", err)
		}
		fmt.Printf("File index: %d\n", ip.LeafIndex)
		fmt.Printf("File name: %s\n", leaf.Name)
		fmt.Printf("Nonce: %x\n", ip.Nonce)
		fmt.Printf("Proof length: %d hashes", len(ip.Proof))
		return nil
	}

	// Info for tree
	fmt.Printf("Root hash: %x\n", t.Root.Hash)
	fmt.Printf("FS root: %s\n", t.Path)
	fmt.Printf("Num. of files: %d\n", len(t.Files))
	fmt.Printf("Creation time: %v\n", t.CreatedAt)
	return nil
}
