package database

import (
	"crypto/tls"
	"net/url"

	"github.com/valkey-io/valkey-go"
)

func NewValkeyClient(uri string) (valkey.Client, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	options := valkey.ClientOption{
		InitAddress: []string{u.Host},
		Username:    username,
		Password:    password,
		TLSConfig:   &tls.Config{},
	}

	return valkey.NewClient(options)
}
