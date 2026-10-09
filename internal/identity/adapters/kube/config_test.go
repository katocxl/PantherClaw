// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR142_ClustersComeOnlyFromOperatorConfiguration: a cluster is an
// https API server with a pinned CA and credential, usable only by the orgs
// it lists; private ranges must be named explicitly.
func TestHR142_ClustersComeOnlyFromOperatorConfiguration(t *testing.T) {
	org := ids.New[ids.Org]()
	good := kube.ClusterConfig{
		Name: "prod", APIServer: "https://10.0.0.1:6443", CAFile: "ca.pem", TokenFile: "token",
		AllowedPrefixes: []string{"10.0.0.0/24"}, Orgs: []string{org.String()},
	}
	d, err := kube.NewDirectory([]kube.ClusterConfig{good})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed("prod", org) || d.Allowed("prod", ids.New[ids.Org]()) || d.Allowed("staging", org) {
		t.Fatal("Allowed must match the cluster and the org")
	}
	if p := good.Prefixes(); len(p) != 1 || p[0].String() != "10.0.0.0/24" {
		t.Fatalf("prefixes %v", p)
	}
	for name, mutate := range map[string]func(*kube.ClusterConfig){
		"http api server":    func(c *kube.ClusterConfig) { c.APIServer = "http://10.0.0.1:6443" },
		"credentials in url": func(c *kube.ClusterConfig) { c.APIServer = "https://admin:pw@10.0.0.1" },
		"path in url":        func(c *kube.ClusterConfig) { c.APIServer = "https://10.0.0.1/api" },
		"no ca":              func(c *kube.ClusterConfig) { c.CAFile = "" },
		"no token":           func(c *kube.ClusterConfig) { c.TokenFile = "" },
		"bad prefix":         func(c *kube.ClusterConfig) { c.AllowedPrefixes = []string{"10.0.0.1"} },
		"no orgs":            func(c *kube.ClusterConfig) { c.Orgs = nil },
		"bad org":            func(c *kube.ClusterConfig) { c.Orgs = []string{"acme"} },
		"bad name":           func(c *kube.ClusterConfig) { c.Name = "Prod Cluster" },
	} {
		c := good
		mutate(&c)
		if _, err := kube.NewDirectory([]kube.ClusterConfig{c}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := kube.NewDirectory([]kube.ClusterConfig{good, good}); err == nil {
		t.Error("a cluster configured twice was accepted")
	}
	var none *kube.Directory
	if none.Allowed("prod", org) {
		t.Error("no configuration allows no cluster")
	}
}
