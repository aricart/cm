package cm

import "strings"

type AccountCache struct {
	emailToAccounts map[string]StringList
	accountToEmails map[string]StringList
}

func NewAccountCache() *AccountCache {
	var ac AccountCache
	ac.emailToAccounts = make(map[string]StringList)
	ac.accountToEmails = make(map[string]StringList)
	return &ac
}

func (ac *AccountCache) Accounts(email string) []string {
	email = strings.ToLower(email)
	return ac.emailToAccounts[email]
}

func (ac *AccountCache) RemoveAll(account string) {
	account = strings.ToUpper(account)
	emails := ac.accountToEmails[account]
	for i, e := range emails {
		emails[i] = strings.ToLower(e)
	}
	// remove all
	delete(ac.accountToEmails, account)
	for _, e := range emails {
		accounts := ac.emailToAccounts[e]
		accounts.Remove(e)
		ac.emailToAccounts[e] = accounts
	}
}

func (ac *AccountCache) Update(account string, emails []string) {
	ac.RemoveAll(account)
	// add the present
	list := ac.accountToEmails[account]
	list.Add(emails...)
	ac.accountToEmails[account] = list
	for _, e := range list {
		accounts := ac.emailToAccounts[e]
		accounts.Add(account)
		ac.emailToAccounts[e] = accounts
	}
}

// StringList is a wrapper for an array of strings
type StringList []string

// Contains returns true if the list contains the string
func (u *StringList) Contains(p string) bool {
	for _, t := range *u {
		if t == p {
			return true
		}
	}
	return false
}

// Add appends 1 or more strings to a list
func (u *StringList) Add(p ...string) {
	for _, v := range p {
		if !u.Contains(v) && v != "" {
			*u = append(*u, v)
		}
	}
}

// Remove removes 1 or more strings from a list
func (u *StringList) Remove(p ...string) {
	for _, v := range p {
		for i, t := range *u {
			if t == v {
				a := *u
				*u = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}
