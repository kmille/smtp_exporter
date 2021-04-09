package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"os/signal"
	"syscall"

	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/kmille/smtp_exporter/config"
	"github.com/kmille/smtp_exporter/prober"
)

var (
	sc = &config.SafeConfig{
		C: &config.Config{},
	}
	configFile    = kingpin.Flag("config.file", "smtp exporter configuration file.").Default("smtp.yml").String()
	configCheck   = kingpin.Flag("config.check", "If true validate the config and then exit.").Default().Bool()
	webConfig     = webflag.AddFlags(kingpin.CommandLine)
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests").Default(":9125").String()
	externalURL   = kingpin.Flag("web.external-url", "The URL under which smtp exporter is externally reachable (for example, if smtp exporter is served via a reverse proxy). Used for generating relative and absolute links back to smtp exporter itself. If the URL has a path portion, it will be used to prefix all HTTP endpoints served by smtp exporter. If omitted, relevant URL components will be derived automatically.").PlaceHolder("<url>").String()
	routePrefix   = kingpin.Flag("web.route-prefix", "Prefix for the internal routes of web endpoints. Defaults to the path of --web.external-url.").PlaceHolder("<path").String()
	historyLimit  = kingpin.Flag("history.limit", "The maximum amount of items to keep in the history.").Default("100").Uint()
	timeoutOffset = kingpin.Flag("timeout-offset", "Offset to subtract from timeout in seconds").Default("0.5").Float64()

	Probers = map[string]prober.ProberFn{
		"smtp": prober.SmtpProber,
		// "smtpd": prober.SmtpdProber,
		// "imap":  prober.ImapProber,
	}

	moduleUnknownCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "smtp_module_unknown_total",
		Help: "Count of unknown modules requested by probes",
	})
)

func probeHandler(w http.ResponseWriter, r *http.Request, c *config.Config, logger log.Logger, rh *resultHistory) {
	moduleName := r.URL.Query().Get("module")

	module, ok := c.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		level.Debug(logger).Log("msg", "Unknown module", "module", moduleName)
		moduleUnknownCounter.Add(1)
		return
	}

	timeoutSeconds, err := getTimeout(r, module, *timeoutOffset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()
	r = r.WithContext(ctx)

	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	params := r.URL.Query()
	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	prober, ok := Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}
	sl := newScrapeLogger(logger, moduleName, target)
	level.Info(sl).Log("msg", "Beginning probe", "probe", module.Prober, "timeout_seconds", timeoutSeconds)

	start := time.Now()
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)
	success := prober(ctx, target, module, registry, sl)
	duration := time.Since(start).Seconds()
	probeDurationGauge.Set(duration)
	if success {
		probeSuccessGauge.Set(1)
		level.Info(sl).Log("msg", "Probe succeeded", "duration_seconds", duration)
	} else {
		level.Info(sl).Log("msg", "Probe failed", "duration_seconds", duration)
	}

	debugOutput := DebugOutput(&module, &sl.buffer, registry)
	rh.Add(moduleName, target, debugOutput, success)

	if r.URL.Query().Get("debug") == "true" {
		w.Header().Set("Conntext-Type", "text/plain")
		w.Write([]byte(debugOutput))
		return
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)

}

type scrapeLogger struct {
	next         log.Logger
	buffer       bytes.Buffer
	bufferLogger log.Logger
}

func newScrapeLogger(logger log.Logger, module string, target string) *scrapeLogger {
	logger = log.With(logger, "module", module, "target", target)
	sl := &scrapeLogger{
		next:   logger,
		buffer: bytes.Buffer{},
	}
	bl := log.NewLogfmtLogger(&sl.buffer)
	sl.bufferLogger = log.With(bl, "ts", log.DefaultTimestampUTC, "caller", log.Caller(6), "module", module, "target", target)
	return sl
}

func (sl scrapeLogger) Log(keyvals ...interface{}) error {
	sl.bufferLogger.Log(keyvals...)
	kvs := make([]interface{}, len(keyvals))
	copy(kvs, keyvals)
	// Switch level to debug for application output
	for i := 0; i < len(kvs); i += 2 {
		if kvs[i] == level.Key() {
			kvs[i+1] = level.DebugValue()
		}
	}
	return sl.next.Log(kvs...)
}

func DebugOutput(module *config.Module, logBuffer *bytes.Buffer, registry *prometheus.Registry) string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Logs for the probe:\n")
	logBuffer.WriteTo(buf)
	fmt.Fprintf(buf, "\n\nMetrics that would have been returned:\n")
	mfs, err := registry.Gather()
	if err != nil {
		fmt.Fprintf(buf, "Error gathering metrics: %s\n", err)
	}
	for _, mf := range mfs {
		expfmt.MetricFamilyToText(buf, mf)
	}
	fmt.Fprintf(buf, "\n\n\nModule configuration:\n")
	c, err := yaml.Marshal(module)
	if err != nil {
		fmt.Fprintf(buf, "Error marshalling config: %s\n", err)
	}
	buf.Write(c)
	return buf.String()

}

func getTimeout(r *http.Request, module config.Module, offset float64) (timeoutSeconds float64, err error) {

	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
	}

	if timeoutSeconds == 0 {
		timeoutSeconds = 120
	}

	var maxTimeOutSeconds = timeoutSeconds - offset
	if module.Timeout.Seconds() < maxTimeOutSeconds && module.Timeout.Seconds() > 0 {
		timeoutSeconds = module.Timeout.Seconds()
	} else {
		timeoutSeconds = maxTimeOutSeconds
	}
	return timeoutSeconds, nil
}

func run() int {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("smtp_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)
	rh := &resultHistory{maxResults: *historyLimit}

	level.Info(logger).Log("msg", "Starting smtp_exporter", "version", version.Info())
	level.Info(logger).Log("build_context", version.BuildContext())

	if err := sc.ReloadConfig(*configFile); err != nil {
		level.Error(logger).Log("msg", "Error loading config", "err", err)
		return 1
	}

	if *configCheck {
		level.Info(logger).Log("msg", "Config file is ok exiting...")
		return 0
	}

	level.Info(logger).Log("msg", "Loaded config file")

	beURL, err := computeExternalURL(*externalURL, *listenAddress)
	if err != nil {
		level.Error(logger).Log("msg", "failed to determine external URL", "err", err)
		return 1
	}
	level.Debug(logger).Log("externalURL", beURL.String())

	// Default --web.route-prefix to --web.external.url
	if *routePrefix == "" {
		*routePrefix = beURL.Path
	}

	// routePrefix must always be at least '/'
	*routePrefix = "/" + strings.Trim(*routePrefix, "/")
	// routerPrefix requires path to have trailing "/" in order
	// for browsers to interpret the path-relative path correctly, instead of stripping it.
	if *routePrefix != "/" {
		*routePrefix = *routePrefix + "/"
	}
	level.Debug(logger).Log("routePrefix", *routePrefix)

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					continue
				}
				level.Info(logger).Log("msg", "Reloaded config file")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Reloaded config file")
					rc <- nil
				}
			}
		}
	}()

	if *routePrefix != "/" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// no other handler matched
			if r.URL.Path != "/" {
				fmt.Println("we are here2")
				http.NotFound(w, r)
				return
			}
			fmt.Println("we are here3")
			fmt.Println("Redirecting to", beURL.String())
			// TODO: is this a bug?
			http.Redirect(w, r, beURL.String(), http.StatusFound)
		})
	}

	http.HandleFunc(path.Join(*routePrefix, "/-/reload"),
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requires a POST request.\n")
				return
			}
			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
			}
		})

	http.Handle(path.Join(*routePrefix, "/metrics"), promhttp.Handler())
	http.HandleFunc(path.Join(*routePrefix, "/-/health"), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
	})

	http.HandleFunc(path.Join(*routePrefix, "/probe"), func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		conf := sc.C
		sc.RUnlock()
		probeHandler(w, r, conf, logger, rh)

	})

	http.HandleFunc(*routePrefix, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("TODO table header"))

		results := rh.List()
		for i := len(results) - 1; i >= 0; i-- {
			r := results[i]
			success := "Success"
			if !r.success {
				success = "<strong>Failure</strong>"
			}
			fmt.Fprintf(w, "<tr><trd>%s</td><td>%s</td><td>%s</td></td><a href='logs?id=%d'>Logs</a></td></tr>",
				html.EscapeString(r.moduleName), html.EscapeString(r.target), success, r.id)
		}

		w.Write([]byte("</table></body></html>"))
	})

	http.HandleFunc(path.Join(*routePrefix, "/logs"), func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil {
			http.Error(w, "Invalid probe id", 400)
			return
		}
		result := rh.Get(id)
		if result != nil {
			http.Error(w, "Probe id not found", 404)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.debugOutput))
	})

	http.HandleFunc(path.Join(*routePrefix, "/config"), func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			level.Warn(logger).Log("msg", "Error marshalling configuration", "err", err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(c)
	})

	srv := &http.Server{Addr: *listenAddress}
	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		level.Info(logger).Log("msg", "Listen on address", "address", *listenAddress)
		if err := web.ListenAndServe(srv, *webConfig, logger); err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
			close(srvc)
		}

	}()

	for {
		select {
		case <-term:
			level.Info(logger).Log("msg", "Received SIGTERM, exiting gracefully...")
			return 0
		case <-srvc:
			return 1
		}
	}
}

func main() {
	os.Exit(run())
}

func init() {
	prometheus.MustRegister(version.NewCollector("smtp_exporter"))
	prometheus.MustRegister(moduleUnknownCounter)
}

func startsOrEndsWithQuote(s string) bool {
	return strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") ||
		strings.HasSuffix(s, "\"") || strings.HasSuffix(s, "'")
}

func computeExternalURL(u, listenAddr string) (*url.URL, error) {
	if u == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("http://%s:%s/", hostname, port)
	}

	if startsOrEndsWithQuote(u) {
		return nil, errors.New("URL must not begin or end with quotes")
	}

	eu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	ppref := strings.TrimRight(eu.Path, "/")
	if ppref != "" && !strings.HasPrefix(ppref, "/") {
		ppref = "/" + ppref
	}
	eu.Path = ppref

	return eu, nil
}
