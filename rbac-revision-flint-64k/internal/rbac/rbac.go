// Package rbac implements the centralized role-based access control matrix.
package rbac

type Action string

const (
	ActionRead   Action = "read"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// permissions maps resource -> role -> allowed actions.
// Access is denied by default for every role/action combination.
var permissions = map[string]map[string][]Action{
	"products": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionCreate, ActionUpdate},
		"viewer":  {ActionRead},
	},
	"prices": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionUpdate},
		"viewer":  {ActionRead},
	},
	"orders": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionCreate, ActionUpdate},
		"viewer":  {ActionRead},
	},
	"customers": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionUpdate},
		"viewer":  {},
	},
	"invoices": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionCreate},
		"viewer":  {ActionRead},
	},
	"payments": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead},
		"viewer":  {},
	},
	"refunds": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionCreate},
		"viewer":  {},
	},
	"inventory": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionUpdate},
		"viewer":  {ActionRead},
	},
	"api-keys": {
		"admin":   {ActionRead, ActionCreate, ActionUpdate, ActionDelete},
		"manager": {},
		"viewer":  {},
	},
	"audit-logs": {
		"admin":   {ActionRead},
		"manager": {ActionRead},
		"viewer":  {},
	},
	"members": {
		"admin":   {ActionRead, ActionUpdate, ActionDelete},
		"manager": {ActionRead, ActionDelete},
		"viewer":  {},
	},
}

func ValidRole(role string) bool {
	switch role {
	case "admin", "manager", "viewer":
		return true
	default:
		return false
	}
}

// Can reports whether the given role may perform the action on the resource.
func Can(role string, resource string, action Action) bool {
	rolePerms, ok := permissions[resource]
	if !ok {
		return false
	}
	actions, ok := rolePerms[role]
	if !ok {
		return false
	}
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}
