package crypto

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

type consumerClosingSink struct {
	consumerTestSink
	closing, finish chan struct{}
}

func (s *consumerClosingSink) Close() error {
	err := s.consumerTestSink.Close()
	close(s.closing)
	<-s.finish
	return err
}

// full_only: false
func TestConsumerPendingClosePreservesOwnerWithoutHoldingRuntimeLock(t *testing.T) {
	selection, route := consumerFixture(t)
	synctest.Test(t, func(t *testing.T) {
		r := newConsumerRuntime(t, route)
		sink := &consumerClosingSink{consumerTestSink: consumerTestSink{id: consumerID("pending close sink")}, closing: make(chan struct{}), finish: make(chan struct{})}
		released := false
		defer func() {
			if !released {
				close(sink.finish)
			}
		}()
		if err := r.admitConsumer(consumerID("admission"), consumerID("purpose"), sink.id, route.CredentialRoute(), selection, sink, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		owner := r.consumer
		owner.cancel()
		select {
		case <-sink.closing:
		case <-time.After(time.Second):
			t.Fatal("cancel did not close the admitted sink")
		}
		if len(owner.selection.Payload.Ciphertext) == 0 || owner.sink != sink {
			t.Fatal("pending sink Close lost its encrypted owner")
		}
		refused := make(chan consumerResult, 1)
		go func() { refused <- r.consume(context.Background(), consumerID("different admission")) }()
		select {
		case result := <-refused:
			if result.code != contract.CryptoInvalidAdmission || result.delivery != consumerDeliveryNone {
				t.Fatal("pending close admitted another consumer", result)
			}
		case <-time.After(time.Second):
			t.Fatal("pending sink Close held the runtime lock")
		}
		retired := make(chan struct{})
		go func() { r.retireConsumer(); close(retired) }()
		synctest.Wait()
		select {
		case <-owner.done:
			t.Fatal("session released an unjoined sink")
		case <-retired:
			t.Fatal("retirement returned before sink Close")
		default:
		}
		close(sink.finish)
		released = true
		select {
		case <-retired:
		case <-time.After(time.Second):
			t.Fatal("retirement did not join completed sink Close")
		}
		if r.slot != nil || owner.sink != nil || owner.selection.Payload.Ciphertext != nil || sink.accepts != 0 || sink.closes != 1 || route.privateCalls != 0 {
			t.Fatal("retirement retained ownership or entered private work")
		}
	})
}
