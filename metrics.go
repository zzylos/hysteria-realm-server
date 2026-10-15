package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsNamespace   = "hysteria_realm"
	eventsRoutePattern = "/v1/{id}/events"
)

type metrics struct {
	reg *prometheus.Registry

	registrations   *prometheus.CounterVec // result
	deregistrations prometheus.Counter
	heartbeats      *prometheus.CounterVec // result
	sessionsExpired prometheus.Counter

	connectRequests  prometheus.Counter
	connectOutcomes  *prometheus.CounterVec // outcome
	connectResponses *prometheus.CounterVec // result
	connectDuration  prometheus.Histogram

	httpRequests *prometheus.CounterVec   // route, method, code
	httpDuration *prometheus.HistogramVec // route
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)
	m := &metrics{reg: reg}

	m.registrations = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "registrations_total",
		Help:      "Realm registration attempts by result (ok, conflict, global_limit, ip_limit, invalid_token, bad_request).",
	}, []string{"result"})
	m.deregistrations = f.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "deregistrations_total",
		Help:      "Explicit realm deregistrations.",
	})
	m.heartbeats = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "heartbeats_total",
		Help:      "Heartbeat requests by result (ok, invalid_token, bad_request).",
	}, []string{"result"})
	m.sessionsExpired = f.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "sessions_expired_total",
		Help:      "Sessions removed by the reaper after TTL expiry (realms that stopped sending heartbeats).",
	})

	m.connectRequests = f.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "connect_requests_total",
		Help:      "Connect (punch brokering) attempts that passed auth and validation. Equals the sum of connect_outcomes_total.",
	})
	m.connectOutcomes = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "connect_outcomes_total",
		Help:      "Connect attempts by outcome (delivered, timeout, no_realm, canceled, rate_limited, ip_rate_limited, nonce_in_use, client_gave_up).",
	}, []string{"outcome"})
	m.connectResponses = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "connect_responses_total",
		Help:      "Punch responses posted back by realm servers, by result (delivered, no_pending).",
	}, []string{"result"})
	m.connectDuration = f.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "connect_duration_seconds",
		Help:      "Time from notifying the realm to receiving its punch response, for delivered connects.",
		Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
	})

	m.httpRequests = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "http_requests_total",
		Help:      "HTTP requests by route pattern, method and status code.",
	}, []string{"route", "method", "code"})
	m.httpDuration = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request handling duration by route pattern (the /events stream is excluded).",
		Buckets:   prometheus.DefBuckets,
	}, []string{"route"})

	return m
}

func (m *metrics) registerGauges(s *server) {
	m.reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "realms_registered",
			Help: "Currently registered realms.",
		}, func() float64 {
			s.mu.Lock()
			defer s.mu.Unlock()
			return float64(len(s.realms))
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "sessions_active",
			Help: "Currently active sessions.",
		}, func() float64 {
			s.mu.Lock()
			defer s.mu.Unlock()
			return float64(len(s.sessions))
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "event_streams_active",
			Help: "Open /events streams — realms currently reachable for punch notifications.",
		}, func() float64 {
			return float64(s.activeEventStreams.Load())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "pending_connects",
			Help: "In-flight connect attempts awaiting a punch response.",
		}, func() float64 {
			return float64(s.pendingConnects.Load())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "global_limit",
			Help: "Configured maximum total realms (0 = unlimited).",
		}, func() float64 {
			return float64(s.maxRealms)
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Name: "ip_limit",
			Help: "Configured maximum realms per client IP (0 = unlimited).",
		}, func() float64 {
			return float64(s.maxRealmsPerIP)
		}),
	)
}

func (m *metrics) registration(result string) {
	if m == nil {
		return
	}
	m.registrations.WithLabelValues(result).Inc()
}

func (m *metrics) deregistration() {
	if m == nil {
		return
	}
	m.deregistrations.Inc()
}

func (m *metrics) heartbeat(result string) {
	if m == nil {
		return
	}
	m.heartbeats.WithLabelValues(result).Inc()
}

func (m *metrics) sessionExpired() {
	if m == nil {
		return
	}
	m.sessionsExpired.Inc()
}

func (m *metrics) connectRequest() {
	if m == nil {
		return
	}
	m.connectRequests.Inc()
}

func (m *metrics) connectOutcome(outcome string) {
	if m == nil {
		return
	}
	m.connectOutcomes.WithLabelValues(outcome).Inc()
}

func (m *metrics) connectResponse(result string) {
	if m == nil {
		return
	}
	m.connectResponses.WithLabelValues(result).Inc()
}

func (m *metrics) observeConnect(d time.Duration) {
	if m == nil {
		return
	}
	m.connectDuration.Observe(d.Seconds())
}

func (m *metrics) httpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "other" // NotFound / MethodNotAllowed
		}
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		m.httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(code)).Inc()
		if route != eventsRoutePattern {
			// Exclude the /events stream from duration metrics,
			// since it's supposed to be long-lived.
			m.httpDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// FlushError lets http.ResponseController report write errors through the
// recorder instead of losing them in Flush.
func (r *statusRecorder) FlushError() error {
	return http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func serveMetrics(addr string, reg *prometheus.Registry) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("metrics server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("metrics server error: %v", err)
	}
}
