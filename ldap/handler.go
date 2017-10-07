package ldap

import (
	cnf "github.com/pintobikez/authentication-service/config/structures"
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"strings"
)

type Client struct {
	Conn   *ldap.Conn
	Config *cnf.LDAPConfig
	IsBind bool
	UserDN string
}

func New(c *cnf.LDAPConfig) *Client {
	return &Client{Conn: nil, IsBind: false, Config: c}
}

// Connect connects to the ldap backend.
func (lc *Client) Connect() error {
	if lc.Conn == nil && lc.Config != nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Config.Host, lc.Config.Port)
		if !lc.Config.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}
			// Reconnect with TLS
			if !lc.Config.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         lc.Config.ServerName,
			}
			//IF there is a certificate configured
			if lc.Config.SSLCert != "" && lc.Config.SSLKey != "" {
				cert, err := tls.LoadX509KeyPair(lc.Config.SSLCert, lc.Config.SSLKey)
				if err != nil {
					return err
				}
				config.Certificates = append(config.Certificates, cert)
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *Client) Close() {
	lc.IsBind = false
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *Client) Authenticate(username, password string) error {
	if lc.Conn != nil {
		err := lc.Connect()
		if err != nil {
			return err
		}
	}

	// Bind as the user to verify their password
	err := lc.Conn.Bind(fmt.Sprintf(lc.Config.BindDN, username), password)
	if err != nil {
		return err
	}

	attributes := []string{"cn"}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.Config.UserFilter, username),
		attributes,
		nil,
	)

	// Perform search for user in LDAP
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil
	}

	// Bind userDN
	lc.UserDN = sr.Entries[0].DN
	lc.IsBind = true

	return nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *Client) GetGroupsOfUser(username string) (map[string]string, error) {

	if !lc.IsBind || lc.UserDN == "" {
		return nil, fmt.Errorf("User %s is not Binded, please Login first", username)
	}

	if lc.Conn != nil {
		err := lc.Connect()
		if err != nil {
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.Config.GroupFilter, lc.UserDN),
		[]string{"cn"},
		nil,
	)
	// Perform search for groups in LDAP
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	// Map the groups
	groups := make(map[string]string)
	for _, entry := range sr.Entries {
		if entry.GetAttributeValue("cn") != "" {
			n := strings.ToUpper(entry.GetAttributeValue("cn"))
			groups[n] = n
		}
	}

	return groups, nil
}

// Health Endpoint of the Client
func (lc *Client) Health() error {

	if lc.Config == nil {
		return fmt.Errorf("LDAP Config file not loaded")
	}

	err := lc.Connect()
	if err != nil {
		return err
	}
	defer lc.Close()

	return nil
}
