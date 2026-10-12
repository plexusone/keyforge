//go:build ignore

// Command generate runs Ent codegen for keyforge's registry schema.
// Run via: go run ./sqlstore/ent/generate.go
package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	err := entc.Generate("./sqlstore/ent/schema", &gen.Config{
		Package: "github.com/plexusone/keyforge/sqlstore/ent",
		Features: []gen.Feature{
			gen.FeatureUpsert,
			gen.FeatureLock,
			gen.FeatureExecQuery,
		},
	})
	if err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}
}
