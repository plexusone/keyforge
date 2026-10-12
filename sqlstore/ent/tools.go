//go:build tools

package ent

// The code generator in generate.go is built with "go:build ignore", so the
// module tool does not see its imports and would drop its dependencies. Naming
// them here keeps them in go.mod.
import (
	_ "entgo.io/ent/entc"
	_ "entgo.io/ent/entc/gen"
)
