package cm

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

type StaticFileResolver struct {
	dir string
}

func NewStaticResolver(dir string) (*StaticFileResolver, error) {
	var r StaticFileResolver
	r.dir = dir
	if err := r.init(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *StaticFileResolver) init() error {
	if _, err := os.Stat(r.dir); os.IsNotExist(err) {
		return os.MkdirAll(r.dir, 0755)
	}
	return nil
}

func (r *StaticFileResolver) StoreAccountConfig(token []byte) (*Config, error) {
	nc, err := ParseConfig(token)
	if err != nil {
		return nc, err
	}
	otoken, err := r.GetConfig(nc.Account)
	if err != nil {
		return nc, err
	}
	var oc *Config
	if otoken != nil {
		oc, err = ParseConfig(otoken)
		if err != nil {
			return nc, err
		}
	}
	// if we have an old static config, but new one is different StoreAccountConfig
	if oc != nil && oc.Kind == Static {
		// if changed type delete all users
		if oc.Kind != nc.Kind {
			r.deleteUserJwts(oc.Account, oc.Users)
		} else {
			deleted := nc.Users.Deleted(oc.Users)
			r.deleteUserJwts(oc.Account, deleted)
		}
	}
	fp := r.calcConfigDir(nc.Account)
	if err := r.ensureDir(fp); err != nil {
		return nc, err
	}
	return nc, ioutil.WriteFile(filepath.Join(fp, nc.Account), token, 0644)
}

func (r *StaticFileResolver) StoreUserJwt(token []byte) error {
	uc, err := jwt.DecodeUserClaims(string(token))
	if err != nil {
		return fmt.Errorf("unable to decode user JWT: %v", err)
	}
	// associate the user with the account that generated the JWT
	id := uc.Issuer
	if uc.IssuerAccount != "" {
		id = uc.IssuerAccount
	}
	// the "email" should be the uc.Name or it won't be found
	fp := r.calcUserDir(uc.Name)
	if err := r.ensureDir(fp); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(fp, id), token, 0644)
}

func (r *StaticFileResolver) GetConfig(account string) ([]byte, error) {
	account = strings.ToUpper(account)
	if !nkeys.IsValidPublicAccountKey(account) {
		return nil, errors.New("not account key")
	}
	dir := r.calcConfigDir(account)
	d, err := ioutil.ReadFile(filepath.Join(dir, account))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
	}
	return d, err
}

func (r *StaticFileResolver) deleteUserJwts(account string, users Users) error {
	for _, i := range users {
		if err := r.deleteUserJwt(account, i.Email); err != nil {
			return err
		}
	}
	return nil
}

func (r *StaticFileResolver) deleteUserJwt(account string, user string) error {
	dir := r.calcUserDir(user)
	return os.Remove(filepath.Join(dir, account))
}
func (r *StaticFileResolver) GetUserJwt(email string, account string) ([]byte, error) {
	account = strings.ToUpper(account)
	ad, err := r.GetConfig(account)
	if err != nil || ad == nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	c, err := ParseConfig(ad)
	if err != nil {
		return nil, err
	}
	var d []byte
	// even if we have a file, we won't release it unless the config says we do
	if c.Kind == Static && c.HasUser(email) {
		fp := filepath.Join(r.calcUserDir(email), account)
		d, err = ioutil.ReadFile(fp)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	return d, err
}

func (r *StaticFileResolver) GetUserAccounts(email string) ([]string, error) {
	email = strings.ToLower(email)
	p := r.calcUserDir(email)
	if !r.dirExists(p) {
		return nil, nil
	}
	infos, err := ioutil.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var accounts []string
	for _, i := range infos {
		n := i.Name()
		// is this is an account public key
		if nkeys.IsValidPublicAccountKey(n) {
			d, err := r.GetConfig(n)
			if err != nil {
				return nil, err
			}
			c, err := ParseConfig(d)
			if err != nil {
				return nil, err
			}
			if c.HasUser(email) {
				accounts = append(accounts, n)
			}
		}
	}
	return accounts, nil
}

func (r *StaticFileResolver) dirExists(v string) bool {
	i, err := os.Stat(v)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && i.IsDir()
}

func (r *StaticFileResolver) ensureDir(d string) error {
	return os.MkdirAll(d, 0755)
}

// calcShard returns a 12 character string on the value specified
func (r *StaticFileResolver) calcShard(v string) string {
	v = strings.ToLower(v)
	h := sha1.New()
	h.Write([]byte(v))
	bin := h.Sum(nil)
	return fmt.Sprintf("%x", bin)[:12]
}

// calcUserDir returns the dir where the user configuration
// would be found if it exists
func (r *StaticFileResolver) calcUserDir(v string) string {
	return filepath.Join(r.dir, "users", r.calcShard(v), v)
}

// calcConfigDir returns the directory where an account
// configuration would be found if it exists
func (r *StaticFileResolver) calcConfigDir(v string) string {
	return filepath.Join(r.dir, "configs", r.calcShard(v), v)
}
