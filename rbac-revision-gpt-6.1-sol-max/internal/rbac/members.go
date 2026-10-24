package rbac

func (s *Server) members(t *tenant, path route, actor string, a action, rawQuery string, body map[string]any, bodyError *apiError) response {
	current, exists := t.Members[path.id]
	if path.id != "" && !exists {
		return failure(notFound("member not found"))
	}
	if a == read {
		if path.id != "" {
			if rawQuery != "" {
				return failure(badInput("query parameters are only supported on lists"))
			}
			return response{status: 200, body: memberJSON(t, path.id)}
		}
		query, err := parseQuery(rawQuery, "members")
		if err != nil {
			return failure(err)
		}
		items := make([]map[string]any, 0)
		for userID := range t.Members {
			item := memberJSON(t, userID)
			if query.matches(item) {
				items = append(items, item)
			}
		}
		return query.page(items)
	}
	if rawQuery != "" {
		return failure(badInput("query parameters are only supported on lists"))
	}
	userID := path.id
	var next role
	if a != remove {
		if bodyError != nil {
			return failure(bodyError)
		}
		for key := range body {
			if key != "role" && !(key == "user_id" && a == create) {
				return failure(badInput("unknown or read-only member field: " + key))
			}
		}
		value, ok := body["role"].(string)
		next = role(value)
		if !ok || !validRole(next) {
			return failure(badInput("role must be admin, manager, or viewer"))
		}
		if a == create {
			userID, ok = body["user_id"].(string)
			if !ok || !validID(userID) {
				return failure(badInput("user_id must be a valid user identifier"))
			}
			if !s.users[userID] {
				return failure(notFound("user not found"))
			}
			if _, exists := t.Members[userID]; exists {
				return failure(conflict("member_exists", "user is already a tenant member"))
			}
		}
	}
	if current == admin && next != admin {
		admins := 0
		for _, r := range t.Members {
			if r == admin {
				admins++
			}
		}
		if admins <= 1 {
			return failure(conflict("last_admin", "the last tenant administrator cannot be removed or demoted"))
		}
	}
	if a == remove {
		delete(t.Members, userID)
		s.store.audit(t, actor, "delete", "members", userID, map[string]any{"previous_role": string(current)})
		return response{status: 204}
	}
	t.Members[userID] = next
	operation, status := "update", 200
	details := map[string]any{"role": string(next), "previous_role": string(current)}
	if a == create {
		operation, status = "create", 201
		delete(details, "previous_role")
	}
	s.store.audit(t, actor, operation, "members", userID, details)
	result := response{status: status, body: memberJSON(t, userID)}
	if a == create {
		result.headers = map[string]string{"Location": "/tenants/" + t.ID + "/members/" + userID}
	}
	return result
}
