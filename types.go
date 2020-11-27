package cm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

const DashboardConfigurationType = "dashboard-account-configuration"

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
	if u == nil {
		return old
	}
	if old == nil {
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

func (gc *GeneratorConfig) GetRole(ur UserRole) *RolePerms {
	for _, r := range gc.Roles {
		if ur == r.Role {
			return &r
		}
	}
	return nil
}

func (gc *GeneratorConfig) AddRole(perms RolePerms) error {
	gc.Roles = append(gc.Roles, perms)
	return gc.Validate()
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
		kp, err := nkeys.FromSeed([]byte(i.SigningKey))
		if err != nil {
			return err
		}
		if err := nkeys.CompatibleKeyPair(kp, nkeys.PrefixByteSeed, nkeys.PrefixByteAccount); err != nil {
			return fmt.Errorf("%q is not a valid signing key", i.SigningKey)
		}
		_, found = keys[i.SigningKey]
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

func (rp *RolePerms) KeyPair() (nkeys.KeyPair, error) {
	return nkeys.FromSeed([]byte(rp.SigningKey))
}

type Config struct {
	Account         string
	Kind            ResolverType
	Users           Users
	GeneratorConfig *GeneratorConfig
}

func (c *Config) HasUser(email string) bool {
	return c.getUser(email) != nil
}

func (c *Config) getUser(email string) *User {
	email = strings.ToLower(email)
	for _, e := range c.Users {
		if strings.ToLower(e.Email) == email {
			return &e
		}
	}
	return nil
}

func (c *Config) ListUsers() StringList {
	var a StringList
	for _, e := range c.Users {
		a.Add(strings.ToLower(e.Email))
	}
	return a
}

func (c *Config) GetUserJwt(email string) (string, error) {
	email = strings.ToLower(email)
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.Kind != Generator {
		return "", errors.New("not generator")
	}
	u := c.getUser(email)
	if u == nil {
		return "", nil
	}
	perms := c.GeneratorConfig.GetRole(u.Role)
	if perms == nil {
		return "", fmt.Errorf("role not found - %s", u.Role.String())
	}

	sk, err := nkeys.FromSeed([]byte(perms.SigningKey))
	if err != nil {
		return "", err
	}

	uc := jwt.NewUserClaims(email)
	uc.BearerToken = true
	uc.IssuerAccount = c.Account
	uc.Sub.Allow = append(uc.Sub.Allow, perms.Sub...)
	uc.Pub.Allow = append(uc.Pub.Allow, perms.Pub...)
	return uc.Encode(sk)
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
	if claim.Type != DashboardConfigurationType {
		return nil, fmt.Errorf("bad claim type - %q", claim.Type)
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
