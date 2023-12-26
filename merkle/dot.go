package merkle

import (
	"fmt"
	"io"
)

// Output tree in DOT language, for rendering with graphviz

func (n *Node) dotNodeName() string {
	// Name the node using a bit of the hash, unless it has a filename
	name := fmt.Sprintf("%x", n.Hash[:3])
	if len(n.Name) > 0 {
		name = n.Name
	}
	return name
}

// getDot just writes the relationships, and not the boilerplate of the graph.
func (n *Node) getDot(w io.Writer) error {
	// Depth-first search

	if n.Left != nil {
		_, err := fmt.Fprintf(w, `"%s" -> "%s"`+"\n", n.dotNodeName(), n.Left.dotNodeName())
		if err != nil {
			return err
		}
		if err := n.Left.getDot(w); err != nil {
			return err
		}
	}
	if n.Right != nil {
		_, err := fmt.Fprintf(w, `"%s" -> "%s"`+"\n", n.dotNodeName(), n.Right.dotNodeName())
		if err != nil {
			return err
		}
		if err := n.Right.getDot(w); err != nil {
			return err
		}
	}
	return nil
}

// DotGraph writes a complete directed graph for the tree that this node is the root of.
// It uses the DOT language. If an error is returned, the written bytes are likely not a valid
// DOT file.
func (n *Node) DotGraph(w io.Writer) error {
	_, err := fmt.Fprintf(w, `digraph "%x" {`+"\n", n.Hash)
	if err != nil {
		return err
	}
	if err := n.getDot(w); err != nil {
		return err
	}
	_, err = fmt.Fprint(w, "}")
	return err
}
