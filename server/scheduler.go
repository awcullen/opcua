package server

import (
	"sync"
	"time"
)

// <AvailableSamplingRates>
// <SamplingRate>0</SamplingRate>
// <SamplingRate>50</SamplingRate>
// <SamplingRate>100</SamplingRate>
// <SamplingRate>250</SamplingRate>
// <SamplingRate>500</SamplingRate>
// <SamplingRate>1000</SamplingRate>
// <SamplingRate>2000</SamplingRate>
// <SamplingRate>5000</SamplingRate>
// <SamplingRate>10000</SamplingRate>
// </AvailableSamplingRates>

type Scheduler struct {
	sync.Mutex
	cancellationCh      chan struct{}
	tickers             map[time.Duration]*PollGroup
	minSamplingInterval time.Duration
}

func NewScheduler(server *Server) *Scheduler {
	s := &Scheduler{sync.Mutex{}, server.closing, make(map[time.Duration]*PollGroup), time.Duration(server.ServerCapabilities().MinSupportedSampleRate) * time.Millisecond}
	return s
}

func (s *Scheduler) GetPollGroup(interval time.Duration) *PollGroup {
	s.Lock()
	defer s.Unlock()
	if interval < s.minSamplingInterval {
		interval = s.minSamplingInterval
	}
	if t, ok := s.tickers[interval]; ok {
		return t
	}
	t := NewPollGroup(interval, s.cancellationCh)
	s.tickers[interval] = t
	return t
}

type PollGroup struct {
	sync.Mutex
	cancellationCh chan struct{}
	interval       time.Duration
	subs           map[PollListener]struct{}
}

func NewPollGroup(interval time.Duration, cancellationCh chan struct{}) *PollGroup {
	b := &PollGroup{
		Mutex:          sync.Mutex{},
		cancellationCh: cancellationCh,
		interval:       interval,
		subs:           map[PollListener]struct{}{},
	}
	go b.run()
	// log.Printf("Opening PollGroup %d ms\n", b.interval.Nanoseconds()/1000000)
	return b
}

func (b *PollGroup) run() {
	ticker := time.NewTicker(b.interval)
	for {
		select {
		case <-b.cancellationCh:
			ticker.Stop()
			b.Lock()
			// log.Printf("Closing PollGroup %d ms with %d subs\n", b.interval.Nanoseconds()/1000000, len(b.subs))
			for sub := range b.subs {
				delete(b.subs, sub)
			}
			b.Unlock()
			return
		case <-ticker.C:
			b.Lock()
			listeners := make([]PollListener, len(b.subs))
			i := 0
			for sub := range b.subs {
				listeners[i] = sub
				i++
			}
			b.Unlock()
			for _, listener := range listeners {
				listener.Poll()
			}
		}
	}
}

func (b *PollGroup) Subscribe(listener PollListener) {
	b.Lock()
	b.subs[listener] = struct{}{}
	b.Unlock()
}

func (b *PollGroup) Unsubscribe(listener PollListener) {
	b.Lock()
	delete(b.subs, listener)
	b.Unlock()
}

type PollListener interface {
	Poll()
}
