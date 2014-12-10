package main

import (
	"fmt"
	"path/filepath"
)

// ACL holds an access control list structure
type ACL struct {
	Permits []string
	Rejects []string
}

// NewACL defines a new named access control list
func NewACL(permit, reject []string) (a *ACL, err error) {
	a = &ACL{
		Permits: permit,
		Rejects: reject,
	}

	// Internal tests to see if the patterns are valid, better have them ripple
	// up here then when using any of the maching functions
	if err = a.test(a.Permits); err != nil {
		return nil, err
	}
	if err = a.test(a.Rejects); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *ACL) match(name string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return false
		}
		if matched {
			return true
		}
	}
	return false
}

func (a *ACL) test(patterns []string) (err error) {
	for _, pattern := range patterns {
		if _, err = filepath.Match(pattern, "."); err != nil {
			return fmt.Errorf("%q: %v", pattern, err)
		}
	}
	return nil
}

// Permitted checks if name is explicitly permitted in the access control list.
func (a *ACL) Permitted(name string) bool {
	return a.match(name, a.Permits)
}

// Rejected checks if name is explicitly rejected in the access control list.
func (a *ACL) Rejected(name string) bool {
	return a.match(name, a.Rejects)
}

// Test checks if name is permitted in the access control list, returns true if
// explicitly permitted or not explicitly rejected.
func (a *ACL) Test(name string) bool {
	if a.Permitted(name) {
		return true
	}
	if a.Rejected(name) {
		return false
	}
	return true
}
