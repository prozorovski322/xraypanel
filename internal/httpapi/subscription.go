package httpapi

import (
	"errors"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/ratelimit"
	"github.com/xraypanel/panel/internal/service"
	"github.com/xraypanel/panel/internal/sublink"
)

// Where the public subscription lives. Outside /api/v1: it is what goes into a client's
// "add subscription" box, and a short, stable URL there is part of the product.
const pathSubscription = "/sub/"

const codeRateLimited = "rate_limited"

// subscriptionHandler serves the public, unauthenticated subscription endpoint. The
// token in the path is the only credential.
type subscriptionHandler struct {
	svc     *service.Service
	logger  *slog.Logger
	limiter *ratelimit.Limiter
}

func (h *subscriptionHandler) routes(r chi.Router) {
	r.Route("/sub/{token}", func(r chi.Router) {
		r.Use(h.limit)
		r.Get("/", h.serve)
		// Several clients send HEAD to read the quota header without the body.
		r.Head("/", h.serve)
		r.Get("/info", h.info)
	})
}

// limit refuses a client that asks too often.
//
// Every request costs a database lookup, and the endpoint answers anyone, so without a
// bound a single client can turn it into load on the panel's one database.
func (h *subscriptionHandler) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.limiter != nil {
			if ok, wait := h.limiter.Allow(clientKey(r.RemoteAddr)); !ok {
				seconds := int(math.Ceil(wait.Seconds()))
				w.Header().Set("Retry-After", strconv.Itoa(max(seconds, 1)))
				writeError(w, r, http.StatusTooManyRequests, codeRateLimited,
					"too many requests, try again later")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientKey is what the limiter counts against: the address, or for IPv6 its /64.
//
// A single IPv6 customer is routinely handed a whole /64 and can pick a fresh address
// from it for every request, so limiting individual IPv6 addresses would limit nothing.
func clientKey(remoteAddr string) string {
	ip := peerIP(remoteAddr)
	if ip == nil {
		return remoteAddr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (h *subscriptionHandler) serve(w http.ResponseWriter, r *http.Request) {
	format := sublink.FormatFor(r.UserAgent())
	if raw := r.URL.Query().Get("format"); raw != "" {
		parsed, ok := sublink.ParseFormat(raw)
		if !ok {
			writeError(w, r, http.StatusBadRequest, codeBadRequest,
				"format must be one of base64, clash, singbox, json")
			return
		}
		format = parsed
	}

	public, ok := h.resolve(w, r)
	if !ok {
		return
	}

	body, err := sublink.Render(public.Subscription, format)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	header := w.Header()
	header.Set("Content-Type", format.ContentType())
	// The body is a set of credentials. Nothing between the panel and the client may keep
	// a copy, and a revocation has to take effect on the next fetch, not after a cache
	// expires.
	header.Set("Cache-Control", "no-store")
	header.Set("Subscription-Userinfo", public.Subscription.UserInfo.UserInfoHeader())
	if public.UpdateIntervalHours > 0 {
		header.Set("Profile-Update-Interval", strconv.Itoa(public.UpdateIntervalHours))
	}
	if title := sublink.ProfileTitleHeader(public.ProfileTitle); title != "" {
		header.Set("Profile-Title", title)
	}
	if disposition := contentDisposition(public.ProfileTitle, format); disposition != "" {
		header.Set("Content-Disposition", disposition)
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body) //nolint:gosec // a client profile served with its own content type, not HTML

	// Recorded only for a fetch that delivered a profile, so that "last fetched" means
	// what an operator reads it as.
	h.svc.MarkSubscriptionFetched(r.Context(), public.User.ID)
}

// contentDisposition names the file for the profile formats. Desktop Clash clients take
// the profile's name from it; for a link list it would only make a browser download
// what it could have shown.
func contentDisposition(title string, format sublink.Format) string {
	var extension string
	switch format {
	case sublink.FormatClash:
		extension = ".yaml"
	case sublink.FormatSingBox:
		extension = ".json"
	default:
		return ""
	}

	name := strings.TrimSpace(title)
	if name == "" {
		name = "subscription"
	}
	// FormatMediaType writes an RFC 2231 filename* for anything outside ASCII.
	return mime.FormatMediaType("attachment", map[string]string{"filename": name + extension})
}

// publicInfo is what the subscription page shows. It carries the links as well, so the
// page needs one request.
type publicInfo struct {
	Username            string       `json:"username"`
	Status              string       `json:"status"`
	TrafficUsed         int64        `json:"traffic_used"`
	TrafficLimit        int64        `json:"traffic_limit"`
	ResetStrategy       string       `json:"reset_strategy"`
	ExpiresAt           *time.Time   `json:"expires_at"`
	ProfileTitle        string       `json:"profile_title"`
	UpdateIntervalHours int          `json:"update_interval_hours"`
	Links               []publicLink `json:"links"`
}

type publicLink struct {
	Remark string `json:"remark"`
	Link   string `json:"link"`
}

func (h *subscriptionHandler) info(w http.ResponseWriter, r *http.Request) {
	public, ok := h.resolve(w, r)
	if !ok {
		return
	}

	links := make([]publicLink, 0, len(public.Subscription.Endpoints))
	for i := range public.Subscription.Endpoints {
		endpoint := &public.Subscription.Endpoints[i]
		uri, err := endpoint.URI()
		if err != nil {
			writeServiceError(w, r, h.logger, err)
			return
		}
		links = append(links, publicLink{Remark: endpoint.Remark, Link: uri})
	}

	user := public.User
	writeJSON(w, http.StatusOK, publicInfo{
		Username:            user.Username,
		Status:              string(public.Status),
		TrafficUsed:         user.TrafficUsed,
		TrafficLimit:        user.TrafficLimit,
		ResetStrategy:       string(user.ResetStrategy),
		ExpiresAt:           user.ExpiresAt,
		ProfileTitle:        public.ProfileTitle,
		UpdateIntervalHours: public.UpdateIntervalHours,
		Links:               links,
	})
}

// resolve looks the token up and answers the request itself when there is nothing to
// serve.
func (h *subscriptionHandler) resolve(w http.ResponseWriter, r *http.Request) (*service.PublicSubscription, bool) {
	public, err := h.svc.SubscriptionByToken(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			// No detail: unknown, malformed and revoked are the same answer, so a probe
			// learns nothing about which tokens once existed.
			writeError(w, r, http.StatusNotFound, codeNotFound, "")
			return nil, false
		}
		writeServiceError(w, r, h.logger, err)
		return nil, false
	}
	return public, true
}
