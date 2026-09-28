package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/auth"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/service"
)

// --- routes ---

func (h *crudHandler) resourceRoutes(r chi.Router, mw *authMiddleware) {
	r.Route("/groups", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/", h.listGroups)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Post("/", h.createGroup)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/{id}", h.getGroup)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Patch("/{id}", h.updateGroup)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Delete("/{id}", h.deleteGroup)
		r.With(mw.requireScope(auth.ScopeUsersWrite)).Post("/{id}/users", h.addUsersToGroup)
	})

	r.Route("/inbounds", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/", h.listInbounds)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Post("/", h.createInbound)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/{id}", h.getInbound)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Patch("/{id}", h.updateInbound)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Delete("/{id}", h.deleteInbound)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/{id}/hosts", h.listInboundHosts)
	})

	r.Route("/hosts", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/", h.listHosts)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Post("/", h.createHost)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/{id}", h.getHost)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Patch("/{id}", h.updateHost)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Delete("/{id}", h.deleteHost)
	})

	r.Route("/reality-keys", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeInboundsRead)).Get("/", h.listRealityKeys)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Post("/", h.createRealityKey)
		r.With(mw.requireScope(auth.ScopeInboundsWrite)).Delete("/{id}", h.deleteRealityKey)
	})

	r.Route("/nodes", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/", h.listNodes)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Post("/", h.createNode)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/{id}", h.getNode)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Patch("/{id}", h.updateNode)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Delete("/{id}", h.deleteNode)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/{id}/inbounds", h.listNodeInbounds)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Put("/{id}/inbounds/{inboundID}", h.attachInbound)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Delete("/{id}/inbounds/{inboundID}", h.detachInbound)
		// The generated configuration is a node secret: it carries every user's
		// credentials and the Reality private key, so it sits behind nodes:write rather
		// than nodes:read.
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Get("/{id}/config", h.previewNodeConfig)

		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/{id}/connection", h.nodeConnection)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/{id}/traffic", h.nodeTraffic)

		// Minting an enrollment token is handing out a node's identity, so it needs
		// write access even though nothing about the node changes.
		r.With(mw.requireScope(auth.ScopeNodesWrite)).Post("/{id}/enrollment-tokens", h.createEnrollmentToken)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/{id}/enrollment-tokens", h.listEnrollmentTokens)
		r.With(mw.requireScope(auth.ScopeNodesWrite)).
			Delete("/{id}/enrollment-tokens/{tokenID}", h.revokeEnrollmentToken)
	})

	r.Route("/pki", func(r chi.Router) {
		r.Use(mw.requireAuth)
		r.With(mw.requireScope(auth.ScopeNodesRead)).Get("/ca", h.certificateAuthority)
	})
}

// --- groups ---

type groupRequest struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	IsDefault   *bool    `json:"is_default"`
	InboundIDs  *[]int64 `json:"inbound_ids"`
}

type groupResponse struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsDefault   bool     `json:"is_default"`
	InboundIDs  []int64  `json:"inbound_ids,omitempty"`
	InboundTags []string `json:"inbound_tags,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

func (h *crudHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.svc.Queries().ListInboundGroups(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	out := make([]groupResponse, 0, len(groups))
	for i := range groups {
		out = append(out, newGroupResponse(&groups[i], nil))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) getGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	group, err := h.svc.Queries().GetInboundGroup(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, translateNotFound(err, "group"))
		return
	}
	inbounds, err := h.svc.Queries().ListGroupInbounds(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newGroupResponse(&group, inbounds))
}

func (h *crudHandler) createGroup(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req groupRequest
	if !decodeBody(w, r, body, &req) {
		return
	}
	if req.Name == nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "name is required")
		return
	}

	in := service.CreateGroupInput{Name: *req.Name}
	if req.Description != nil {
		in.Description = *req.Description
	}
	if req.IsDefault != nil {
		in.IsDefault = *req.IsDefault
	}
	if req.InboundIDs != nil {
		in.InboundIDs = *req.InboundIDs
	}

	group, err := h.svc.CreateGroup(r.Context(), actorFrom(r), in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, newGroupResponse(group, nil))
}

func (h *crudHandler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req groupRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.UpdateGroupInput{
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
	}
	if req.InboundIDs != nil {
		in.SetInbounds = true
		in.InboundIDs = *req.InboundIDs
	}

	group, err := h.svc.UpdateGroup(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newGroupResponse(group, nil))
}

func (h *crudHandler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteGroup(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *crudHandler) addUsersToGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		UserIDs []int64 `json:"user_ids"`
	}
	if !decodeBody(w, r, body, &req) {
		return
	}

	added, err := h.svc.AddUsersToGroup(r.Context(), actorFrom(r), id, req.UserIDs)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added})
}

func newGroupResponse(group *dbgen.InboundGroup, inbounds []dbgen.Inbound) groupResponse {
	response := groupResponse{
		ID:          group.ID,
		Name:        group.Name,
		Description: group.Description,
		IsDefault:   group.IsDefault,
		CreatedAt:   group.CreatedAt.UTC().Format(time.RFC3339),
	}
	for i := range inbounds {
		response.InboundIDs = append(response.InboundIDs, inbounds[i].ID)
		response.InboundTags = append(response.InboundTags, inbounds[i].Tag)
	}
	return response
}

// --- inbounds ---

type createInboundRequest struct {
	Tag             string          `json:"tag"`
	Protocol        string          `json:"protocol"`
	Transport       string          `json:"transport"`
	Security        string          `json:"security"`
	ListenPort      int32           `json:"listen_port"`
	ListenAddress   string          `json:"listen_address"`
	Flow            string          `json:"flow"`
	SSMethod        string          `json:"ss_method"`
	SSServerKey     string          `json:"ss_server_key"`
	NetworkSettings json.RawMessage `json:"network_settings"`
	TLSSettings     json.RawMessage `json:"tls_settings"`
	Sniffing        json.RawMessage `json:"sniffing"`
	Extra           json.RawMessage `json:"extra"`
	RealityKeyID    *int64          `json:"reality_key_id"`
	Enabled         *bool           `json:"enabled"`
}

type updateInboundRequest struct {
	Tag             *string         `json:"tag"`
	ListenPort      *int32          `json:"listen_port"`
	ListenAddress   *string         `json:"listen_address"`
	NetworkSettings json.RawMessage `json:"network_settings"`
	TLSSettings     json.RawMessage `json:"tls_settings"`
	Sniffing        json.RawMessage `json:"sniffing"`
	Extra           json.RawMessage `json:"extra"`
	Enabled         *bool           `json:"enabled"`

	// Flow distinguishes absent from an explicit null, which clears it.
	Flow optional[string] `json:"flow"`
}

type inboundResponse struct {
	ID              int64           `json:"id"`
	Tag             string          `json:"tag"`
	Protocol        string          `json:"protocol"`
	Transport       string          `json:"transport"`
	Security        string          `json:"security"`
	ListenPort      int32           `json:"listen_port"`
	ListenAddress   string          `json:"listen_address"`
	Flow            string          `json:"flow,omitempty"`
	SSMethod        string          `json:"ss_method,omitempty"`
	NetworkSettings json.RawMessage `json:"network_settings"`
	TLSSettings     json.RawMessage `json:"tls_settings"`
	Sniffing        json.RawMessage `json:"sniffing"`
	Extra           json.RawMessage `json:"extra"`
	RealityKeyID    *int64          `json:"reality_key_id,omitempty"`
	Enabled         bool            `json:"enabled"`
	CreatedAt       string          `json:"created_at"`
}

func (h *crudHandler) listInbounds(w http.ResponseWriter, r *http.Request) {
	inbounds, err := h.svc.Queries().ListInbounds(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	out := make([]inboundResponse, 0, len(inbounds))
	for i := range inbounds {
		out = append(out, newInboundResponse(&inbounds[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) getInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	inbound, err := h.svc.Queries().GetInbound(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, translateNotFound(err, "inbound"))
		return
	}
	writeJSON(w, http.StatusOK, newInboundResponse(&inbound))
}

func (h *crudHandler) createInbound(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createInboundRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	// Enabled defaults to true: an inbound created switched off is almost never what
	// someone meant, and the field can still be sent explicitly.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	inbound, err := h.svc.CreateInbound(r.Context(), actorFrom(r), service.CreateInboundInput{
		Tag:             req.Tag,
		Protocol:        req.Protocol,
		Transport:       req.Transport,
		Security:        req.Security,
		ListenPort:      req.ListenPort,
		ListenAddr:      req.ListenAddress,
		Flow:            req.Flow,
		SSMethod:        req.SSMethod,
		SSServerKey:     req.SSServerKey,
		NetworkSettings: req.NetworkSettings,
		TLSSettings:     req.TLSSettings,
		Sniffing:        req.Sniffing,
		Extra:           req.Extra,
		RealityKeyID:    req.RealityKeyID,
		Enabled:         enabled,
	})
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, newInboundResponse(inbound))
}

func (h *crudHandler) updateInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req updateInboundRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.UpdateInboundInput{
		Tag:             req.Tag,
		ListenPort:      req.ListenPort,
		ListenAddr:      req.ListenAddress,
		NetworkSettings: req.NetworkSettings,
		TLSSettings:     req.TLSSettings,
		Sniffing:        req.Sniffing,
		Extra:           req.Extra,
		Enabled:         req.Enabled,
	}
	if req.Flow.Present() {
		in.SetFlow = true
		in.Flow = req.Flow.ValueOr("")
	}

	inbound, err := h.svc.UpdateInbound(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newInboundResponse(inbound))
}

func (h *crudHandler) deleteInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteInbound(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newInboundResponse(inbound *dbgen.Inbound) inboundResponse {
	response := inboundResponse{
		ID:              inbound.ID,
		Tag:             inbound.Tag,
		Protocol:        string(inbound.Protocol),
		Transport:       string(inbound.Transport),
		Security:        string(inbound.Security),
		ListenPort:      inbound.ListenPort,
		ListenAddress:   inbound.ListenAddress,
		NetworkSettings: json.RawMessage(inbound.NetworkSettings),
		TLSSettings:     json.RawMessage(inbound.TlsSettings),
		Sniffing:        json.RawMessage(inbound.Sniffing),
		Extra:           json.RawMessage(inbound.Extra),
		RealityKeyID:    inbound.RealityKeyID,
		Enabled:         inbound.IsEnabled,
		CreatedAt:       inbound.CreatedAt.UTC().Format(time.RFC3339),
	}
	if inbound.Flow != nil {
		response.Flow = *inbound.Flow
	}
	if inbound.SsMethod != nil {
		response.SSMethod = *inbound.SsMethod
	}
	// The Shadowsocks server key is never returned. It is stored encrypted and it is a
	// server secret; it reaches clients only inside a subscription link.
	return response
}

// --- hosts ---

type hostRequest struct {
	InboundID     int64           `json:"inbound_id"`
	Remark        *string         `json:"remark"`
	Address       *string         `json:"address"`
	Port          optional[int32] `json:"port"`
	SNI           *string         `json:"sni"`
	HostHeader    *string         `json:"host_header"`
	Path          *string         `json:"path"`
	Fingerprint   *string         `json:"fingerprint"`
	ALPN          *string         `json:"alpn"`
	AllowInsecure *bool           `json:"allow_insecure"`
	SortOrder     *int32          `json:"sort_order"`
	Enabled       *bool           `json:"enabled"`
}

type hostResponse struct {
	ID            int64  `json:"id"`
	InboundID     int64  `json:"inbound_id"`
	Remark        string `json:"remark"`
	Address       string `json:"address"`
	Port          *int32 `json:"port,omitempty"`
	SNI           string `json:"sni,omitempty"`
	HostHeader    string `json:"host_header,omitempty"`
	Path          string `json:"path,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	ALPN          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allow_insecure"`
	SortOrder     int32  `json:"sort_order"`
	Enabled       bool   `json:"enabled"`
}

func (h *crudHandler) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.svc.Queries().ListHosts(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, hostResponses(hosts))
}

func (h *crudHandler) listInboundHosts(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	hosts, err := h.svc.Queries().ListHostsForInbound(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, hostResponses(hosts))
}

func (h *crudHandler) getHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	host, err := h.svc.Queries().GetHost(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, translateNotFound(err, "host"))
		return
	}
	writeJSON(w, http.StatusOK, newHostResponse(&host))
}

func (h *crudHandler) createHost(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req hostRequest
	if !decodeBody(w, r, body, &req) {
		return
	}
	if req.Remark == nil || req.Address == nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "remark and address are required")
		return
	}

	in := service.CreateHostInput{
		InboundID:   req.InboundID,
		Remark:      *req.Remark,
		Address:     *req.Address,
		SNI:         req.SNI,
		HostHeader:  req.HostHeader,
		Path:        req.Path,
		Fingerprint: req.Fingerprint,
		ALPN:        req.ALPN,
		Enabled:     true,
	}
	if req.Port.Present() {
		in.Port = req.Port.Value()
	}
	if req.AllowInsecure != nil {
		in.AllowInsecure = *req.AllowInsecure
	}
	if req.SortOrder != nil {
		in.SortOrder = *req.SortOrder
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}

	host, err := h.svc.CreateHost(r.Context(), actorFrom(r), in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, newHostResponse(host))
}

func (h *crudHandler) updateHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req hostRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.UpdateHostInput{
		Remark:        req.Remark,
		Address:       req.Address,
		SNI:           req.SNI,
		HostHeader:    req.HostHeader,
		Path:          req.Path,
		Fingerprint:   req.Fingerprint,
		ALPN:          req.ALPN,
		AllowInsecure: req.AllowInsecure,
		SortOrder:     req.SortOrder,
		Enabled:       req.Enabled,
	}
	if req.Port.Present() {
		in.SetPort = true
		in.Port = req.Port.Value()
	}

	host, err := h.svc.UpdateHost(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newHostResponse(host))
}

func (h *crudHandler) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteHost(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func hostResponses(hosts []dbgen.Host) []hostResponse {
	out := make([]hostResponse, 0, len(hosts))
	for i := range hosts {
		out = append(out, newHostResponse(&hosts[i]))
	}
	return out
}

func newHostResponse(host *dbgen.Host) hostResponse {
	response := hostResponse{
		ID:            host.ID,
		InboundID:     host.InboundID,
		Remark:        host.Remark,
		Address:       host.Address,
		Port:          host.Port,
		AllowInsecure: host.AllowInsecure,
		SortOrder:     host.SortOrder,
		Enabled:       host.IsEnabled,
	}
	response.SNI = derefString(host.Sni)
	response.HostHeader = derefString(host.HostHeader)
	response.Path = derefString(host.Path)
	response.Fingerprint = derefString(host.Fingerprint)
	response.ALPN = derefString(host.Alpn)
	return response
}

// --- reality keys ---

type createRealityKeyRequest struct {
	Name         string   `json:"name"`
	Dest         string   `json:"dest"`
	ServerNames  []string `json:"server_names"`
	ShortIDCount int      `json:"short_id_count"`
}

type realityKeyResponse struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	PublicKey   string   `json:"public_key"`
	ShortIDs    []string `json:"short_ids"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	CreatedAt   string   `json:"created_at"`
}

func (h *crudHandler) listRealityKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.Queries().ListRealityKeys(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	out := make([]realityKeyResponse, 0, len(keys))
	for i := range keys {
		out = append(out, newRealityKeyResponse(&keys[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) createRealityKey(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createRealityKeyRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	key, err := h.svc.CreateRealityKey(r.Context(), actorFrom(r), service.CreateRealityKeyInput{
		Name:         req.Name,
		Dest:         req.Dest,
		ServerNames:  req.ServerNames,
		ShortIDCount: req.ShortIDCount,
	})
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, newRealityKeyResponse(key))
}

func (h *crudHandler) deleteRealityKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteRealityKey(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newRealityKeyResponse never includes the private key. It is what makes the inbound
// impersonate its target, and a leaked one lets anyone run an identical server.
func newRealityKeyResponse(key *dbgen.RealityKey) realityKeyResponse {
	return realityKeyResponse{
		ID:          key.ID,
		Name:        key.Name,
		PublicKey:   key.PublicKey,
		ShortIDs:    key.ShortIds,
		Dest:        key.Dest,
		ServerNames: key.ServerNames,
		CreatedAt:   key.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// --- nodes ---

type nodeRequest struct {
	Name        *string          `json:"name"`
	Address     *string          `json:"address"`
	CountryCode *string          `json:"country_code"`
	Tag         *string          `json:"tag"`
	ConfigPatch *json.RawMessage `json:"config_patch"`
	Enabled     *bool            `json:"enabled"`
}

type nodeResponse struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	Address        string          `json:"address"`
	CountryCode    string          `json:"country_code,omitempty"`
	Tag            string          `json:"tag"`
	Status         string          `json:"status"`
	XrayVersion    string          `json:"xray_version,omitempty"`
	AgentVersion   string          `json:"agent_version,omitempty"`
	ConfigPatch    json.RawMessage `json:"config_patch"`
	ConfigVersion  int64           `json:"config_version"`
	AppliedVersion *int64          `json:"applied_version,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	TrafficUsed    int64           `json:"traffic_used"`
	Enabled        bool            `json:"enabled"`
	LastSeenAt     string          `json:"last_seen_at,omitempty"`
	CreatedAt      string          `json:"created_at"`
}

func (h *crudHandler) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.svc.Queries().ListNodes(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	out := make([]nodeResponse, 0, len(nodes))
	for i := range nodes {
		out = append(out, newNodeResponse(&nodes[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) getNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	node, err := h.svc.Queries().GetNode(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, translateNotFound(err, "node"))
		return
	}
	writeJSON(w, http.StatusOK, newNodeResponse(&node))
}

func (h *crudHandler) createNode(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req nodeRequest
	if !decodeBody(w, r, body, &req) {
		return
	}
	if req.Name == nil || req.Address == nil {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "name and address are required")
		return
	}

	in := service.CreateNodeInput{Name: *req.Name, Address: *req.Address, Enabled: true}
	if req.CountryCode != nil {
		in.CountryCode = *req.CountryCode
	}
	if req.Tag != nil {
		in.Tag = *req.Tag
	}
	if req.ConfigPatch != nil {
		in.ConfigPatch = *req.ConfigPatch
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}

	node, err := h.svc.CreateNode(r.Context(), actorFrom(r), in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, newNodeResponse(node))
}

func (h *crudHandler) updateNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req nodeRequest
	if !decodeBody(w, r, body, &req) {
		return
	}

	in := service.UpdateNodeInput{
		Name:        req.Name,
		Address:     req.Address,
		CountryCode: req.CountryCode,
		Tag:         req.Tag,
		Enabled:     req.Enabled,
	}
	if req.ConfigPatch != nil {
		in.SetConfigPatch = true
		in.ConfigPatch = *req.ConfigPatch
	}

	node, err := h.svc.UpdateNode(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, newNodeResponse(node))
}

func (h *crudHandler) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteNode(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *crudHandler) listNodeInbounds(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	inbounds, err := h.svc.Queries().ListNodeInbounds(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	out := make([]inboundResponse, 0, len(inbounds))
	for i := range inbounds {
		out = append(out, newInboundResponse(&inbounds[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) attachInbound(w http.ResponseWriter, r *http.Request) {
	nodeID, inboundID, ok := nodeInboundIDs(w, r)
	if !ok {
		return
	}
	if err := h.svc.AttachInbound(r.Context(), actorFrom(r), nodeID, inboundID); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *crudHandler) detachInbound(w http.ResponseWriter, r *http.Request) {
	nodeID, inboundID, ok := nodeInboundIDs(w, r)
	if !ok {
		return
	}
	if err := h.svc.DetachInbound(r.Context(), actorFrom(r), nodeID, inboundID); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// previewNodeConfig returns the configuration a node would receive.
//
// Without this, the only way to find out whether a configuration is valid is to deploy it
// and see whether the node comes back.
func (h *crudHandler) previewNodeConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	generated, err := h.svc.PreviewNodeConfig(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"structural_hash": generated.StructuralHash,
		"inbound_hashes":  generated.InboundHashes,
		"config":          json.RawMessage(generated.JSON),
	})
}

func nodeInboundIDs(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	nodeID, ok := pathID(w, r)
	if !ok {
		return 0, 0, false
	}
	inboundID, err := strconv.ParseInt(chi.URLParam(r, "inboundID"), 10, 64)
	if err != nil || inboundID <= 0 {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "inboundID must be a positive integer")
		return 0, 0, false
	}
	return nodeID, inboundID, true
}

func newNodeResponse(node *dbgen.Node) nodeResponse {
	response := nodeResponse{
		ID:             node.ID,
		Name:           node.Name,
		Address:        node.Address,
		Tag:            node.Tag,
		Status:         string(node.Status),
		ConfigPatch:    json.RawMessage(node.ConfigPatch),
		ConfigVersion:  node.ConfigVersion,
		AppliedVersion: node.AppliedVersion,
		LastError:      node.LastError,
		TrafficUsed:    node.TrafficUsed,
		Enabled:        node.IsEnabled,
		CreatedAt:      node.CreatedAt.UTC().Format(time.RFC3339),
	}
	response.CountryCode = derefString(node.CountryCode)
	response.XrayVersion = derefString(node.XrayVersion)
	response.AgentVersion = derefString(node.AgentVersion)
	response.LastSeenAt = formatOptionalTime(node.LastHeartbeatAt)
	// The certificate fingerprint is omitted: it is the node's identity, and publishing
	// it over an admin API serves no purpose the node name does not.
	return response
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// translateNotFound turns a raw pgx no-rows error from a direct query into the service's
// not-found error, so handlers that read without the service layer report the same way.
func translateNotFound(err error, what string) error {
	if err == nil {
		return nil
	}
	return service.WrapNotFound(err, what)
}
