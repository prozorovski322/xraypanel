package httpapi

import (
	"net/http"
	"time"

	"github.com/xraypanel/panel/internal/service"
)

// Traffic history is read-only and deliberately coarse: the daily rollup, not the hourly
// rows. The hourly table is the billing ledger and is pruned on a retention window; the
// daily one is what a chart is drawn from and what an operator compares against an invoice.

// defaultTrafficWindow is what a caller gets without asking.
const defaultTrafficWindow = 30 * 24 * time.Hour

// maxTrafficWindow bounds one request. A year of days for one user is a few hundred rows,
// which is a report rather than a chart, and an unbounded window is an easy way to make the
// panel do unbounded work.
const maxTrafficWindow = 366 * 24 * time.Hour

type trafficDayResponse struct {
	Day      string `json:"day"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

type trafficHistoryResponse struct {
	From string               `json:"from"`
	To   string               `json:"to"`
	Days []trafficDayResponse `json:"days"`

	// Totals save every caller from summing the days themselves and getting it subtly
	// wrong in a different way each time.
	TotalUplink   int64 `json:"total_uplink"`
	TotalDownlink int64 `json:"total_downlink"`
}

func (h *crudHandler) userTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	from, to, ok := trafficWindow(w, r)
	if !ok {
		return
	}

	history, err := h.svc.UserTrafficHistory(r.Context(), id, from, to)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, trafficResponse(from, to, history))
}

func (h *crudHandler) nodeTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	from, to, ok := trafficWindow(w, r)
	if !ok {
		return
	}

	history, err := h.svc.NodeTrafficHistory(r.Context(), id, from, to)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, trafficResponse(from, to, history))
}

// trafficWindow reads the from/to query parameters.
func trafficWindow(w http.ResponseWriter, r *http.Request) (from, to time.Time, ok bool) {
	query := r.URL.Query()
	now := time.Now().UTC()

	to = now
	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.DateOnly, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest, "to must be a date as YYYY-MM-DD")
			return time.Time{}, time.Time{}, false
		}
		to = parsed.UTC()
	}

	from = to.Add(-defaultTrafficWindow)
	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.DateOnly, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, codeBadRequest, "from must be a date as YYYY-MM-DD")
			return time.Time{}, time.Time{}, false
		}
		from = parsed.UTC()
	}

	if from.After(to) {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "from must not be after to")
		return time.Time{}, time.Time{}, false
	}
	if to.Sub(from) > maxTrafficWindow {
		writeError(w, r, http.StatusBadRequest, codeBadRequest,
			"the window must be at most a year")
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

func trafficResponse(from, to time.Time, history []service.UserTrafficByDay) trafficHistoryResponse {
	response := trafficHistoryResponse{
		From: from.Format(time.DateOnly),
		To:   to.Format(time.DateOnly),
		Days: make([]trafficDayResponse, 0, len(history)),
	}
	for _, day := range history {
		response.Days = append(response.Days, trafficDayResponse{
			Day:      day.Day.Format(time.DateOnly),
			Uplink:   day.Uplink,
			Downlink: day.Downlink,
		})
		response.TotalUplink += day.Uplink
		response.TotalDownlink += day.Downlink
	}
	return response
}
