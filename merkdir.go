package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

// Set by goreleaser or just
var (
	version string
	commit  string
	date    string
	builtBy string
)

func main() {
	app := &cli.App{
		Name:  "merkdir",
		Usage: "create merkle trees of your directories",
		Commands: []*cli.Command{
			{
				Name:  "version",
				Usage: "get version information",
				Action: func(ctx *cli.Context) error {
					fmt.Printf("%s\n%s\n%s\n%s\n", version, commit, date, builtBy)
					return nil
				},
			},
			{
				Name:   "gen",
				Usage:  "generate a merkle tree",
				Action: gen,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Usage:    "output tree file",
						Required: true,
					},
				},
				Before: func(ctx *cli.Context) error {
					// Validate path argument
					if ctx.Args().Len() != 1 {
						return fmt.Errorf("only one argument allowed: dir path")
					}
					if fi, err := os.Stat(ctx.Args().First()); err == nil && fi.IsDir() {
						return nil
					}
					return fmt.Errorf("not a valid path to a directory")
				},
			},
			{
				Name:   "root",
				Usage:  "get the root hash for a tree or inclusion proof",
				Action: root,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "hex",
						Usage: "get hash as hex",
					},
				},
				Before: func(ctx *cli.Context) error {
					// Validate path argument
					if ctx.Args().Len() != 1 {
						return fmt.Errorf("only one argument allowed: file path")
					}
					return nil
				},
			},
			{
				Name:   "inclusion",
				Usage:  "generate an inclusion proof given a tree and file in that tree",
				Action: inclusion,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "tree",
						Usage:    "input tree file",
						Aliases:  []string{"t"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "file",
						Usage:    "file path as stored in the tree",
						Aliases:  []string{"f"},
						Required: true,
					},
					&cli.StringFlag{
						Name:    "output",
						Usage:   "output path for inclusion proof (otherwise text version goes to stdout)",
						Aliases: []string{"o"},
					},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						return fmt.Errorf("command requires no arguments")
					}
					return nil
				},
			},
			{
				Name:   "verify-file",
				Usage:  "check if a file on disk is still part of the merkle tree",
				Action: verifyFile,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "tree",
						Usage:    "input tree file",
						Aliases:  []string{"t"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "name",
						Usage:    "name/path of file in merkle tree",
						Aliases:  []string{"n"},
						Required: true,
					},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						return fmt.Errorf("command requires no arguments")
					}
					return nil
				},
			},
			{
				Name:   "verify-inclusion",
				Usage:  "get the root hash for a given inclusion proof and file",
				Action: verifyInclusion,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "proof",
						Usage:    "inclusion proof file",
						Aliases:  []string{"p"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "file",
						Usage:    "path to leaf file",
						Aliases:  []string{"f"},
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "hex",
						Usage: "get hash as hex",
					},
					&cli.StringFlag{
						Name:  "hash",
						Usage: "hex root hash to compare to",
					},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						return fmt.Errorf("command requires no arguments")
					}
					return nil
				},
			},
			{
				Name:   "info",
				Usage:  "get information about a tree, or tree and inclusion proof.",
				Action: info,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "proof",
						Usage:   "inclusion proof file",
						Aliases: []string{"p"},
					},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						return fmt.Errorf("command requires one arg: the tree file")
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
