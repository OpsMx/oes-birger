package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/opsmx/oes-birger/pkg/serviceconfig"
	"github.com/opsmx/oes-birger/pkg/tunnel"
	"github.com/opsmx/oes-birger/pkg/tunnelroute"
	"github.com/opsmx/oes-birger/pkg/ulid"
	"github.com/tevino/abool"
)

var (
	ulidContext = ulid.NewContext()
)

func runHTTPServer(service serviceconfig.IncomingServiceConfig) {
	log.Printf("Running service HTTP listener on port %d", service.Port)

	mux := http.NewServeMux()

	mux.HandleFunc("/", serviceAPIHandlerMaker(service))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", service.Port),
		Handler: mux,
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func serviceAPIHandlerMaker(service serviceconfig.IncomingServiceConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := tunnelroute.Search{
			Name:         service.Destination,
			EndpointType: service.ServiceType,
			EndpointName: service.DestinationService,
		}
		runAPIHandler(ep, w, r)
	}
}

type apiHandlerState struct {
	seenHeader bool
	isChunked  bool
	flusher    http.Flusher
	cleanClose abool.AtomicBool
}

func copyHeaders(resp *tunnel.HttpTunnelResponse, w http.ResponseWriter) {
	for name := range w.Header() {
		w.Header().Del(name)
	}
	for _, header := range resp.Headers {
		for _, value := range header.Values {
			w.Header().Add(header.Name, value)
		}
	}
}

func handleDone(n <-chan struct{}, state apiHandlerState, target tunnelroute.Search, id string) {
	<-n
	if state.cleanClose.IsNotSet() {
		err := routes.Cancel(target, id)
		if err != nil {
			log.Printf("while cancelling http request: %v", err)
		}
	}
}

func runAPIHandler(ep tunnelroute.Search, w http.ResponseWriter, r *http.Request) {
	transactionID := ulidContext.Ulid()

	body, _ := ioutil.ReadAll(r.Body)
	req := &tunnel.OpenHTTPTunnelRequest{
		Id:      transactionID,
		Type:    ep.EndpointType,
		Name:    ep.EndpointName,
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: tunnel.MakeHeaders(r.Header),
		Body:    body,
	}
	message := &tunnelroute.HTTPMessage{Out: make(chan *tunnel.MessageWrapper), Cmd: req}
	sessionID, found := routes.Send(ep, message)
	if !found {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ep.Session = sessionID

	var handlerState apiHandlerState
	notify := r.Context().Done()
	go handleDone(notify, handlerState, ep, transactionID)

	handlerState.flusher = w.(http.Flusher)
	for {
		in, more := <-message.Out
		if !more {
			if !handlerState.seenHeader {
				log.Printf("Request timed out sending to agent")
				w.WriteHeader(http.StatusBadGateway)
			}
			handlerState.cleanClose.Set()
			return
		}

		switch x := in.Event.(type) {
		case *tunnel.MessageWrapper_HttpTunnelControl:
			handleTunnelControl(handlerState, x.HttpTunnelControl, w, r)
		case nil:
			// ignore for now
		default:
			log.Printf("Received unknown message: %T", x)
		}
	}
}

func handleTunnelControl(state apiHandlerState, tunnelControl *tunnel.HttpTunnelControl, w http.ResponseWriter, r *http.Request) {
	switch controlMessage := tunnelControl.ControlType.(type) {
	case *tunnel.HttpTunnelControl_HttpTunnelResponse:
		resp := controlMessage.HttpTunnelResponse
		state.seenHeader = true
		state.isChunked = resp.ContentLength < 0
		copyHeaders(resp, w)
		w.WriteHeader(int(resp.Status))
		if resp.ContentLength == 0 {
			state.cleanClose.Set()
			return
		}
	case *tunnel.HttpTunnelControl_HttpTunnelChunkedResponse:
		resp := controlMessage.HttpTunnelChunkedResponse
		if !state.seenHeader {
			log.Printf("Error: got ChunkedResponse before HttpResponse")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if len(resp.Body) == 0 {
			state.cleanClose.Set()
			return
		}
		n, err := w.Write(resp.Body)
		if err != nil {
			log.Printf("Error: cannot write: %v", err)
			if !state.seenHeader {
				w.WriteHeader(http.StatusBadGateway)
			}
			return
		}
		if n != len(resp.Body) {
			log.Printf("Error: did not write full message: %d of %d written", n, len(resp.Body))
			if !state.seenHeader {
				w.WriteHeader(http.StatusBadGateway)
			}
			return
		}
		if state.isChunked {
			state.flusher.Flush()
		}
	case nil:
		// ignore for now
	default:
		log.Printf("Received unknown HTTP control message: %T", controlMessage)
	}
}
