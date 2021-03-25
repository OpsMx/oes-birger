package main

import (
	"context"
	"log"
	"sync"
)

var cancelRegistry = struct {
	sync.Mutex
	m map[string]context.CancelFunc
}{m: make(map[string]context.CancelFunc)}

func registerCancelFunction(id string, cancel context.CancelFunc) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	cancelRegistry.m[id] = cancel
}

func unregisterCancelFunction(id string) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	delete(cancelRegistry.m, id)
}

func callCancelFunction(id string) {
	cancelRegistry.Lock()
	defer cancelRegistry.Unlock()
	cancel, ok := cancelRegistry.m[id]
	if ok {
		cancel()
		log.Printf("Cancelling request %s", id)
	}
}
