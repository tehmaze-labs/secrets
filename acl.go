package main

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
)

// ACL holds an access control list structure
type ACL struct {
	PermitHosts []string
	PermitCIDRs []*net.IPNet
	RejectHosts []string
	RejectCIDRs []*net.IPNet
}

// ACls ...
type ACLs map[string]*ACL

// parseIPNets takes a list of strings and parses the CIDR network addresses
func parseIPNets(cidrs []string) (ipnets []*net.IPNet, err error) {
	ipnets = []*net.IPNet{}
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ipnets = append(ipnets, ipnet)
	}
	return
}

// NewACL defines a new named access control list
func NewACL(ph, pc, rh, rc []string) (a *ACL, err error) {
	pcp, err := parseIPNets(pc)
	if err != nil {
		return nil, err
	}
	rcp, err := parseIPNets(rc)
	if err != nil {
		return nil, err
	}

	a = &ACL{
		PermitHosts: ph,
		PermitCIDRs: pcp,
		RejectHosts: rh,
		RejectCIDRs: rcp,
	}

	// Internal tests to see if the patterns are valid, better have them ripple
	// up here then when using any of the maching functions
	if err = a.test(a.PermitHosts); err != nil {
		return nil, err
	}
	if err = a.test(a.RejectHosts); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *ACL) matchCIDR(addr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(addr)
	for _, ipnet := range cidrs {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *ACL) matchHost(name string, patterns []string) bool {
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

// PermitCIDR adds a permitted CIDR address to the ACL.
func (a *ACL) PermitCIDR(cidr *net.IPNet) {
	a.PermitCIDRs = append(a.PermitCIDRs, cidr)
}

// PermitHost adds a permitted host mask to the ACL.
func (a *ACL) PermitHost(name string) {
	a.PermitHosts = append(a.PermitHosts, name)
}

// RejectCIDR adds a rejected CIDR address to the ACL.
func (a *ACL) RejectCIDR(cidr *net.IPNet) {
	a.RejectCIDRs = append(a.RejectCIDRs, cidr)
}

// RejectHost adds a rejected host mask to the ACL.
func (a *ACL) RejectHost(name string) {
	a.RejectHosts = append(a.RejectHosts, name)
}

// PermittedAddr checks if the addr is explicitly permitted in the access control list.
func (a *ACL) PermittedAddr(addr string) bool {
	return a.matchCIDR(addr, a.PermitCIDRs)
}

// PermittedHost checks if the name is explicitly permitted in the access control list.
func (a *ACL) PermittedHost(name string) bool {
	return a.matchHost(name, a.PermitHosts)
}

// RejectedAddr checks if the name is explicitly rejected in the access control list.
func (a *ACL) RejectedAddr(addr string) bool {
	return a.matchCIDR(addr, a.RejectCIDRs)
}

// RejectedHost checks if the name is explicitly rejected in the access control list.
func (a *ACL) RejectedHost(name string) bool {
	return a.matchHost(name, a.RejectHosts)
}

// TestAddr checks if name is permitted in the access control list, returns true
// if explicitly permitted or not explicitly rejected.
func (a *ACL) TestAddr(addr string) bool {
	if a.PermittedAddr(addr) {
		return true
	}
	if a.RejectedAddr(addr) {
		return false
	}
	return true
}

// TestHost checks if name is permitted in the access control list, returns true
// if explicitly permitted or not explicitly rejected.
func (a *ACL) TestHost(name string) bool {
	if a.PermittedHost(name) {
		return true
	}
	if a.RejectedHost(name) {
		return false
	}
	return true
}

func (acls ACLs) GroupPermitted(g *Group, addr string) bool {
	addr, _, _ = net.SplitHostPort(addr)
	for _, name := range g.ACLs {
		if acls[name] != nil {
			if acls[name].PermittedAddr(addr) {
				log.Printf("group %s: %s permitted\n", g, addr)
				return true
			}
		}
	}
	log.Printf("group %s: %s rejected\n", g, addr)
	return false
}
