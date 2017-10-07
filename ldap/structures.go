package ldap

type ClientI interface {
	Authenticate(username, password string) error
	GetGroupsOfUser(username string) (map[string]string, error)
	Connect() error
	Close()
	Health() error
}
