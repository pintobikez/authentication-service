package structures

type LDAPConfig struct {
	BaseDN      string `yaml:"baseDN"`
	BindDN      string `yaml:"bindDN"`
	GroupFilter string `yaml:"groupFilter"`
	UserFilter  string `yaml:"userFilter"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	ServerName  string `yaml:"servername"`
	UseSSL      bool   `yaml:"useSSL,omitempty"`
	SkipTLS     bool   `yaml:"skipTLS,omitempty"`
	SSLKey      string `yaml:"ssl-key,omitempty"`
	SSLCert     string `yaml:"ssl-cert,omitempty"`
}

type SecurityConfig struct {
	CipherKey string `yaml:"cipherkey"`
	TTL       int    `yaml:"ttl"`
}

type RedisConfig struct {
	Mode     string `yaml:"mode"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	TTL      int    `yaml:"ttl"`
	APITTL   int    `yaml:"ttlapi"`
	APIKey   string `yaml:"apikey"`
	TokenKey string `yaml:"tokenkey"`
}
