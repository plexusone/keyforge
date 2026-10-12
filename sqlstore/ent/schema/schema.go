// Package schema is keyforge's Ent schema: the registry's records.
//
// States are stored as small integers whose values are those of the Go
// constants in package registry and package keyforge, and the partial unique
// indexes below refer to them by value. Changing a constant is a stored-format
// change.
//
// Optional times are NULL, never the zero time, so that "not yet" is
// distinguishable from "the year 1".
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
)

// idType maps a 16-byte identifier to a raw byte column in each engine.
var idType = map[string]string{dialect.Postgres: "bytea", dialect.SQLite: "blob"}

func idField(name string) ent.Field {
	return field.Other(name, envelope.ID{}).SchemaType(idType)
}

// Values the partial indexes refer to. They are the numeric values of
// registry.KeyActive, registry.VersionActive and the like.
const (
	keyActive     = "1" // registry.KeyActive
	versionActive = "2" // registry.VersionActive
)

// KEK is a key-encryption key.
type KEK struct{ ent.Schema }

// Fields of KEK.
func (KEK) Fields() []ent.Field {
	return []ent.Field{
		field.Other("id", envelope.ID{}).SchemaType(idType).Immutable(),
		field.String("purpose").NotEmpty(),
		field.String("provider").NotEmpty(),
		field.String("provider_ref").NotEmpty(),
		field.Uint8("state"),
		field.Time("created_at"),
	}
}

// Edges of KEK.
func (KEK) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("versions", KEKVersion.Type).Ref("kek"),
		edge.From("data_keys", DataKey.Type).Ref("kek"),
		edge.From("sentinels", Sentinel.Type).Ref("kek"),
	}
}

// Indexes of KEK.
func (KEK) Indexes() []ent.Index {
	return []ent.Index{
		// At most one active KEK per purpose, enforced by the database.
		index.Fields("purpose").Unique().
			Annotations(entsql.IndexWhere("state = " + keyActive)),
	}
}

// KEKVersion is one version of a KEK.
type KEKVersion struct{ ent.Schema }

// Fields of KEKVersion.
func (KEKVersion) Fields() []ent.Field {
	return []ent.Field{
		idField("kek_id"),
		field.Uint32("version"),
		field.Uint8("state"),
		field.String("provider_ref").Default(""),
		field.Time("created_at"),
		field.Time("activated_at").Optional().Nillable(),
		field.Time("rotated_at").Optional().Nillable(),
		field.Time("retire_after").Optional().Nillable(),
	}
}

// Edges of KEKVersion.
func (KEKVersion) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("kek", KEK.Type).Field("kek_id").Unique().Required(),
	}
}

// Indexes of KEKVersion.
func (KEKVersion) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kek_id", "version").Unique(),
		// At most one active version per KEK, enforced by the database, so two
		// concurrent activations cannot both succeed.
		index.Fields("kek_id").Unique().
			Annotations(entsql.IndexWhere("state = " + versionActive)),
	}
}

// DataKey is a data-encryption key, held wrapped.
type DataKey struct{ ent.Schema }

// Fields of DataKey.
func (DataKey) Fields() []ent.Field {
	return []ent.Field{
		field.Other("id", envelope.ID{}).SchemaType(idType).Immutable(),
		field.String("purpose").NotEmpty(),
		// subject is empty for a purpose-wide key; NULL would defeat the unique
		// indexes, since NULLs are distinct.
		field.String("subject").Default(""),
		field.Uint32("epoch"),
		field.Uint8("algorithm"),
		idField("kek_id"),
		field.Uint32("kek_version"),
		field.Bytes("wrapped").Optional(),
		field.Uint8("state"),
		field.Uint64("reserved").Default(0),
		field.Time("created_at"),
		field.JSON("wrapped_under", []keyforge.KEKVersionRef{}),
		// is_current marks the epoch writes use, which is not always the one in
		// state active: a current key can be marked compromised.
		field.Bool("is_current").Default(false),
	}
}

// Edges of DataKey.
func (DataKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("kek", KEK.Type).Field("kek_id").Unique().Required(),
	}
}

// Indexes of DataKey.
func (DataKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("purpose", "subject", "epoch").Unique(),
		// One current key per purpose and subject, enforced by the database.
		index.Fields("purpose", "subject").Unique().
			Annotations(entsql.IndexWhere("is_current")),
		// References to a KEK version, counted before retirement.
		index.Fields("kek_id", "kek_version"),
		index.Fields("purpose", "state"),
	}
}

// Sentinel is the sealed marker kept for a KEK version.
type Sentinel struct{ ent.Schema }

// Fields of Sentinel.
func (Sentinel) Fields() []ent.Field {
	return []ent.Field{
		idField("kek_id"),
		field.Uint32("version"),
		field.Text("envelope"),
		field.Time("created_at"),
	}
}

// Edges of Sentinel.
func (Sentinel) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("kek", KEK.Type).Field("kek_id").Unique().Required(),
	}
}

// Indexes of Sentinel.
func (Sentinel) Indexes() []ent.Index {
	return []ent.Index{index.Fields("kek_id", "version").Unique()}
}

// Shred is the record of a subject's erasure.
type Shred struct{ ent.Schema }

// Fields of Shred.
func (Shred) Fields() []ent.Field {
	return []ent.Field{
		field.String("purpose").NotEmpty(),
		field.String("subject").NotEmpty(),
		field.Time("requested_at"),
		field.JSON("versions", []keyforge.KEKVersionRef{}),
		field.Int("deks").Default(0),
		field.Time("completed_at").Optional().Nillable(),
	}
}

// Indexes of Shred.
func (Shred) Indexes() []ent.Index {
	return []ent.Index{index.Fields("purpose", "subject").Unique()}
}
