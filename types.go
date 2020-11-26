package cm

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"strings"
)

type UserAccountRequest struct {
	Email string `json:"email"`
}

type UserAccountResponse struct {
	UserAccountRequest
	UserJwtResponse
	Accounts []string `json:"accounts"`
	Error    string   `json:"error"`
}

type UserJwtRequest struct {
	Email   string `json:"email"`
	Account string `json:"account"`
}

type UserJwtResponse struct {
	UserJwtRequest
	Jwt   string `json:"jwt"`
	Error string `json:"error"`
}

type RegisterUserRequest struct {
	Jwt string `json:"jwt"`
}

type RegisterUserResponse struct {
	Error string `json:"error"`
}

type ResolverType int

const (
	Static ResolverType = iota
	Generator
)

const Unknown = "unknown"

func (rt ResolverType) String() string {
	switch rt {
	case Static:
		return "static"
	case Generator:
		return "generator"
	default:
		return Unknown
	}
}

type UserRole int

const (
	// Default is no role - static user JWT
	Owner UserRole = iota + 1
	Manager
	Monitor
)

func (ur UserRole) String() string {
	switch ur {
	case Owner:
		return "owner"
	case Manager:
		return "manager"
	case Monitor:
		return "manager"
	default:
		return Unknown
	}
}

type Users []User
type User struct {
	Email string   `json:"email"`
	Role  UserRole `json:"role,omitempty"`
}

func (u Users) Deleted(old Users) Users {
	if u == nil || old == nil {
		return nil
	}
	m := make(map[string]string)
	for _, i := range u {
		m[i.Email] = i.Email
	}
	var deleted Users
	for _, i := range old {
		_, ok := m[i.Email]
		if !ok {
			deleted = append(deleted, i)
		}
	}
	return deleted
}

type ResolverConfig struct {
	Kind           ResolverType `json:"kind"`
	ResolverConfig interface{}  `json:"config"`
	Users          Users        `json:"users"`
}

func (rc *ResolverConfig) Map() (map[string]interface{}, error) {
	d, err := json.Marshal(rc)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, err
	}
	return m, nil
}

type GeneratorConfig struct {
	Roles []RolePerms `json:"roles"`
}

func (gc *GeneratorConfig) Validate() error {
	if len(gc.Roles) == 0 {
		return errors.New("invalid role count")
	}
	rk := make(map[UserRole]UserRole)
	keys := make(map[string]string)
	for _, i := range gc.Roles {
		n := i.Role.String()
		if n == Unknown {
			return fmt.Errorf("invalid role")
		}
		_, found := rk[i.Role]
		if found {
			return fmt.Errorf("role %s is multiply defined", i.Role.String())
		}
		sk := strings.ToUpper(i.SigningKey)
		if !nkeys.IsValidPublicAccountKey(sk) {
			return fmt.Errorf("%q is not a valid signing key", sk)
		}
		_, found = keys[sk]
		if found {
			return fmt.Errorf("signing key %s is multiply defined", i.SigningKey)
		}
	}
	return nil
}

type RolePerms struct {
	Role       UserRole `json:"role"`
	SigningKey string   `json:"signing_key"`
	Pub        []string `json:"pub_permissions"`
	Sub        []string `json:"sub_permissions"`
}

type Config struct {
	Account         string
	Kind            ResolverType
	Users           Users
	GeneratorConfig *GeneratorConfig
}

func (c *Config) HasUser(email string) bool {
	email = strings.ToLower(email)
	for _, e := range c.Users {
		if strings.ToLower(e.Email) == email {
			return true
		}
	}
	return false
}

func (c *Config) Validate() error {
	c.Account = strings.ToUpper(c.Account)
	if !nkeys.IsValidPublicAccountKey(c.Account) {
		return fmt.Errorf("%q is not a valid signing key", c.Account)
	}
	if c.Kind.String() == Unknown {
		return fmt.Errorf("unknown resolver type")
	}
	if c.Kind != Generator && c.GeneratorConfig != nil {
		return fmt.Errorf("non generator configs cannot have a generator")
	}
	if c.Kind == Generator {
		if c.GeneratorConfig == nil {
			return fmt.Errorf("nil generator config")
		}
		for _, rc := range c.GeneratorConfig.Roles {
			if c.Account == strings.ToUpper(rc.SigningKey) {
				return fmt.Errorf("generator signing keys cannot be account key")
			}
		}
		return c.GeneratorConfig.Validate()
	}
	return nil
}

// ParseConfig returns a resolver configuration that can be used
// to resolve credential requests
func ParseConfig(token []byte) (*Config, error) {
	claim, err := jwt.DecodeGeneric(string(token))
	if err != nil {
		return nil, err
	}

	// expecting a resolver configuration
	if claim.Data == nil {
		return nil, errors.New("bad configuration")
	}

	// re-serialize config to JSON
	c, err := json.Marshal(claim.Data)
	if err != nil {
		return nil, err
	}
	var rc ResolverConfig
	if err := json.Unmarshal(c, &rc); err != nil {
		return nil, err
	}

	var config Config
	config.Account = claim.Issuer
	config.Kind = rc.Kind
	config.Users = rc.Users
	if config.Kind == Generator {
		cc, err := json.Marshal(rc.ResolverConfig)
		if err != nil {
			return nil, err
		}
		var gc GeneratorConfig
		if err := json.Unmarshal(cc, &gc); err != nil {
			return nil, err
		}
		config.GeneratorConfig = &gc
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}
