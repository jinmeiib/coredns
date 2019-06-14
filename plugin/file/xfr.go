package file

import (
	"context"
	"fmt"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Xfr serves up an AXFR.
type Xfr struct {
	*Zone
}

func (x Xfr) xfrOut(state request.Request, records []dns.RR, w dns.ResponseWriter, r *dns.Msg, ch chan<- *dns.Envelope) {
	defer close(ch)

	j, l := 0, 0
	records = append(records, records[0]) // add closing SOA to the end
	log.Infof("Outgoing transfer of %d records of zone %s to %s started", len(records), x.origin, state.IP())
	for i, r := range records {
		l += dns.Len(r)
		if l > transferLength {
			ch <- &dns.Envelope{RR: records[j:i]}
			l = 0
			j = i
		}
	}
	if j < len(records) {
		ch <- &dns.Envelope{RR: records[j:]}
	}
}

// ServeDNS implements the plugin.Handler interface.
func (x Xfr) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// After responding to an xfr query we won't accept any more query on the connection; the client would normally close the connection anyway.
	defer w.Close()

	state := request.Request{W: w, Req: r}
	if !x.TransferAllowed(state) {
		return dns.RcodeServerFailure, nil
	}
	if state.QType() != dns.TypeAXFR && state.QType() != dns.TypeIXFR {
		return 0, plugin.Error(x.Name(), fmt.Errorf("xfr called with non transfer type: %d", state.QType()))
	}

	records := x.All()
	if len(records) == 0 {
		return dns.RcodeServerFailure, nil
	}

	tr := new(dns.Transfer)
	ch := make(chan *dns.Envelope)
	done := make(chan struct{})
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		tr.Out(w, r, ch)
	}()

	// Pass all records to the goroutine, which will send the response to the client.
	// We can't return and close the connection until it completes as the goroutine uses it.
	x.xfrOut(state, records, w, r, ch)
	<-done

	return dns.RcodeSuccess, nil
}

// Name implements the plugin.Handler interface.
func (x Xfr) Name() string { return "xfr" }

const transferLength = 1000 // Start a new envelop after message reaches this size in bytes. Intentionally small to test multi envelope parsing.
