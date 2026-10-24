package model

import "time"

// Base carries the fields shared by all resource entities.
type Base struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Membership struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Role     string `json:"role"`
}

type User struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Role     string `json:"role"`
}

type Product struct {
	Base
	SKU         string  `json:"sku"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Price       float64 `json:"price"`
	Currency    string  `json:"currency"`
}

type Price struct {
	Base
	ProductID string  `json:"productId"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
}

type OrderItem struct {
	ProductID string  `json:"productId"`
	Quantity  int     `json:"quantity"`
	UnitPrice float64 `json:"unitPrice"`
}

type Order struct {
	Base
	CustomerID string      `json:"customerId"`
	Status     string      `json:"status"`
	Items      []OrderItem `json:"items"`
	Total      float64     `json:"total"`
	CreatedBy  string      `json:"createdBy"`
}

type Customer struct {
	Base
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Invoice struct {
	Base
	OrderID    string  `json:"orderId"`
	CustomerID string  `json:"customerId"`
	Status     string  `json:"status"`
	Amount     float64 `json:"amount"`
}

type Payment struct {
	Base
	InvoiceID string  `json:"invoiceId"`
	OrderID   string  `json:"orderId,omitempty"`
	Amount    float64 `json:"amount"`
	Status    string  `json:"status"`
	Method    string  `json:"method"`
}

type Refund struct {
	Base
	PaymentID string  `json:"paymentId"`
	OrderID   string  `json:"orderId,omitempty"`
	Amount    float64 `json:"amount"`
	Reason    string  `json:"reason,omitempty"`
	Status    string  `json:"status"`
}

type InventoryItem struct {
	Base
	ProductID string `json:"productId"`
	Quantity  int    `json:"quantity"`
	Reserved  int    `json:"reserved"`
}

type ApiKey struct {
	Base
	Name   string `json:"name"`
	KeyID  string `json:"keyId"`
	Secret string `json:"secret"`
	Status string `json:"status"`
}

type AuditLog struct {
	Base
	Action   string `json:"action"`
	Actor    string `json:"actor"`
	Resource string `json:"resource"`
	Details  string `json:"details,omitempty"`
}
