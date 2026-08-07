// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseCanonicalIPv4PrefixesJSON(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name:  "empty list",
			value: "[]",
			want:  []netip.Prefix{},
		},
		{
			name:  "canonical IPv4 prefixes",
			value: `["192.0.2.0/28","10.0.0.0/8"]`,
			want: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/28"),
				netip.MustParsePrefix("10.0.0.0/8"),
			},
		},
		{
			name:    "malformed JSON",
			value:   "[",
			wantErr: true,
		},
		{
			name:    "null is not a list",
			value:   "null",
			wantErr: true,
		},
		{
			name:    "host bits are set",
			value:   `["192.0.2.1/24"]`,
			wantErr: true,
		},
		{
			name:    "IPv6 is unsupported",
			value:   `["2001:db8::/32"]`,
			wantErr: true,
		},
		{
			name:    "address lacks prefix length",
			value:   `["192.0.2.1"]`,
			wantErr: true,
		},
		{
			name:    "noncanonical prefix length",
			value:   `["192.0.2.0/024"]`,
			wantErr: true,
		},
		{
			name:    "surrounding whitespace",
			value:   `[" 192.0.2.0/24"]`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCanonicalIPv4PrefixesJSON("scanner-allowed-cidrs-json", test.value)
			if test.wantErr {
				if err == nil {
					t.Fatal("parseCanonicalIPv4PrefixesJSON() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCanonicalIPv4PrefixesJSON() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseCanonicalIPv4PrefixesJSON() = %#v, want %#v", got, test.want)
			}
		})
	}
}
