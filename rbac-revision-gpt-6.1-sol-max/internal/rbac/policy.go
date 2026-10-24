package rbac

type role string

const (
	admin   role = "admin"
	manager role = "manager"
	viewer  role = "viewer"
)

type action uint8

const (
	read action = 1 << iota
	create
	update
	remove
)

// Permissions apply equally to collection, item, and nested routes. Missing
// entries deny access. Ownership and tenant membership are checked separately.
var permissions = map[role]map[string]action{
	admin: {
		"products":   read | create | update | remove,
		"prices":     read | create | update | remove,
		"orders":     read | create | update | remove,
		"customers":  read | create | update | remove,
		"invoices":   read | create | update | remove,
		"payments":   read | create | update | remove,
		"refunds":    read | create | update | remove,
		"inventory":  read | create | update | remove,
		"api-keys":   read | create | update | remove,
		"audit-logs": read,
		"members":    read | create | update | remove,
	},
	manager: {
		"products":   read | create | update,
		"prices":     read | update,
		"orders":     read | create | update,
		"customers":  read | update,
		"invoices":   read | create,
		"payments":   read,
		"refunds":    read | create,
		"inventory":  read | update,
		"audit-logs": read,
	},
	viewer: {
		"products":  read,
		"prices":    read,
		"orders":    read,
		"invoices":  read,
		"inventory": read,
	},
}

func allowed(r role, resource string, a action) bool {
	return a != 0 && permissions[r][resource]&a == a
}

func validRole(r role) bool {
	return r == admin || r == manager || r == viewer
}

func visible(r role, userID string, item *record) bool {
	if !allowed(r, item.Resource, read) {
		return false
	}
	if r == viewer && (item.Resource == "orders" || item.Resource == "invoices") {
		return item.OwnerID == userID
	}
	return true
}
