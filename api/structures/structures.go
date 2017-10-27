package structures

type AuthenticateRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Service  string   `json:"service"`
	Groups   []string `json:"groups"`
}

type AuthenticateResponse struct {
	Token string `json:"token"`
}

type HealthStatus struct {
	Ldap     *HealthStatusDetail `json:"ldapClient"`
	Redis    *HealthStatusDetail `json:"redisClient"`
	Security *HealthStatusDetail `json:"securityConfig"`
}

type HealthStatusDetail struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
