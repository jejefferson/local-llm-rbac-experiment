package rbac

// This file encodes the authorization model: the three roles, the verbs,
// and the public permission matrix. It is the single source of truth for
// "who may do what". The HTTP layer and the in-memory store both consult
// this table so that authorization is centralized and default-deny.

// Verb is a bitflag describing a class of operation on a resource.
type Verb int

const (
	VerbNone   Verb = 0
	VerbRead   Verb = 1 << iota // R
	VerbCreate                  // C
	VerbUpdate                  // U
	VerbDelete                  // D
)

// Union returns the combination of the given verbs.
func Union(verbs ...Verb) Verb {
	var v Verb
	for _, x := range verbs {
		v |= x
	}
	return v
}

// Allows reports whether v contains all of bits.
func (v Verb) Allows(bits Verb) bool { return v&bits == bits }

// Role is an authorization role within a tenant.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleManager
	RoleAdmin
)

// Name returns the wire form of a role.
func (r Role) Name() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleManager:
		return "manager"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseRole converts a role string to a Role. Unknown values are rejected.
func ParseRole(s string) (Role, bool) {
	switch s {
	case "viewer":
		return RoleViewer, true
	case "manager":
		return RoleManager, true
	case "admin":
		return RoleAdmin, true
	default:
		return RoleNone, false
	}
}

// validRole reports whether s is one of the three known roles.
func validRole(s string) bool {
	_, ok := ParseRole(s)
	return ok
}

// resourcePerms captures, for a single resource, the verbs granted to each
// role and whether reads are scoped to the actor's own records.
type resourcePerms struct {
	admin     Verb
	manager   Verb
	viewer    Verb
	ownerOnly bool // owner restriction applies to a role's reads when set
}

// The public permission matrix (source of truth), reproduced programmatically.
//
//	R   = read/list
//	C   = create
//	U   = update
//	D   = delete
//
// "own ... only" is encoded as ownerOnly, which is enforced for the viewer.
var permTable = map[string]resourcePerms{
	"products": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: Union(VerbRead, VerbCreate, VerbUpdate),
		viewer:  VerbRead,
	},
	"prices": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: Union(VerbRead, VerbUpdate),
		viewer:  VerbRead,
	},
	"orders": {
		admin:     Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager:   Union(VerbRead, VerbCreate, VerbUpdate),
		viewer:    VerbRead,
		ownerOnly: true, // viewer: own orders only
	},
	"customers": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: Union(VerbRead, VerbUpdate),
		viewer:  VerbNone,
	},
	"invoices": {
		admin:     Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager:   Union(VerbRead, VerbCreate),
		viewer:    VerbRead,
		ownerOnly: true, // viewer: own invoices only
	},
	"payments": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: VerbRead,
		viewer:  VerbNone,
	},
	"refunds": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: Union(VerbRead, VerbCreate),
		viewer:  VerbNone,
	},
	"inventory": {
		admin:   Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		manager: Union(VerbRead, VerbUpdate),
		viewer:  VerbRead,
	},
	"api-keys": {
		admin: Union(VerbRead, VerbCreate, VerbUpdate, VerbDelete),
		// manager and viewer have no access
	},
	"audit-logs": {
		admin:   VerbRead,
		manager: VerbRead,
		// viewer has no access; audit logs are read-only for every role
	},
}

// knownResources lists the ten public resource types in canonical order.
var knownResources = []string{
	"products",
	"prices",
	"orders",
	"customers",
	"invoices",
	"payments",
	"refunds",
	"inventory",
	"api-keys",
	"audit-logs",
}

// IsKnownResource reports whether name is one of the ten public resources.
func IsKnownResource(name string) bool {
	_, ok := permTable[name]
	return ok
}

// RoleFor returns the verbs granted to role on resource.
func (rp resourcePerms) verbsFor(role Role) Verb {
	switch role {
	case RoleAdmin:
		return rp.admin
	case RoleManager:
		return rp.manager
	case RoleViewer:
		return rp.viewer
	default:
		return VerbNone
	}
}

// union returns the set of verbs granted to any role on the resource. It is
// used to distinguish "method not allowed for anyone" (405) from "method
// allowed, but this role lacks it" (403).
func (rp resourcePerms) union() Verb {
	return rp.admin | rp.manager | rp.viewer
}

// Decision is the centralized authorization result for a (role, resource,
// verb) triple.
type Decision struct {
	Allow        bool
	OwnerOnly    bool // reads are scoped to records owned by the actor
	UnknownOwner bool // true when the role/resource is unknown (defensive); unused for known resources
}

// decideResource applies the permission matrix plus the default-deny rule.
func decideResource(resource string, role Role, verb Verb) Decision {
	rp, ok := permTable[resource]
	if !ok {
		// Unknown resource types are rejected outright (treated as 404 at the
		// router level); defensively deny here too.
		return Decision{Allow: false}
	}
	granted := rp.verbsFor(role)
	allow := role != RoleNone && granted.Allows(verb)
	return Decision{
		Allow:     allow,
		OwnerOnly: allow && rp.ownerOnly && role == RoleViewer,
	}
}

// canAccess reports whether the role may perform verb on resource, and whether
// (allowed) reads are owner-scoped.
func canAccess(resource string, role Role, verb Verb) (allow bool, ownerOnly bool) {
	d := decideResource(resource, role, verb)
	return d.Allow, d.OwnerOnly
}

// unionVerbs returns the verbs permitted by any role on the resource; used for
// 405 detection. Returns false if the resource is unknown.
func unionVerbs(resource string) (Verb, bool) {
	rp, ok := permTable[resource]
	if !ok {
		return 0, false
	}
	return rp.union(), true
}
