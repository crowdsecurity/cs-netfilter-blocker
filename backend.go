package main

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/sqlite"
	log "github.com/sirupsen/logrus"
)

type backend interface {
	Init() error
	ShutDown() error
	Run(*sqlite.Context, time.Duration) error
}

type backendCtx struct {
	ctx backend
}

func (b *backendCtx) Init() error {
	err := b.ctx.Init()
	if err != nil {
		return err
	}
	return nil
}

func (b *backendCtx) Run(dbCTX *sqlite.Context, frequency time.Duration) error {
	err := b.ctx.Run(dbCTX, frequency)
	if err != nil {
		log.Fatalf(err.Error())
	}
	return nil
}

func (b *backendCtx) ShutDown() error {
	err := b.ctx.ShutDown()
	if err != nil {
		return err
	}
	return nil
}

func newBackend(backendType string) (*backendCtx, error) {
	var ok bool
	ctx := &backendCtx{}
	log.Printf("backend type : %s", backendType)
	if backendType == "iptables" {
		tmpCtx, err := newIPTables()
		if err != nil {
			return nil, err
		}
		ctx.ctx, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("interface iptables is not good")
		}
	}
	return ctx, nil
}
