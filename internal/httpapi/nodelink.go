package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xraypanel/panel/internal/nodegrpc"
)

// NodeRegistry is the live view of which nodes have an open control stream.
//
// An interface rather than the concrete registry so that the HTTP layer can be built
// without a gRPC server at all, which is what the handler tests do.
type NodeRegistry interface {
	Status(nodeID int64) (nodegrpc.NodeStatus, bool)
	Count() int
}

// --- enrollment tokens ---

// enrollmentResponse is returned once, when a token is minted.
//
// It carries three fields and not just the token, because a token on its own is not
// enough to join safely: a node that cannot verify the panel before sending its token
// gives that token to whoever answers on the address. The pin is what lets it verify.
type enrollmentResponse struct {
	TokenID int64 `json:"token_id"`
	NodeID  int64 `json:"node_id"`

	// Token is shown exactly once. The panel stores only its hash.
	Token string `json:"token"`

	CAPin      string `json:"ca_pin"`
	ServerName string `json:"server_name"`
	ExpiresAt  string `json:"expires_at"`
}

type enrollmentTokenResponse struct {
	ID        int64  `json:"id"`
	NodeID    int64  `json:"node_id"`
	ExpiresAt string `json:"expires_at"`
	UsedAt    string `json:"used_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (h *crudHandler) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	// The lifetime is not a request parameter. It is a security property of the
	// installation, configured once, rather than something the caller minting a
	// credential gets to widen per request.
	enrollment, err := h.svc.CreateEnrollmentToken(r.Context(), actorFrom(r), id, 0)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, enrollmentResponse{
		TokenID:    enrollment.TokenID,
		NodeID:     enrollment.NodeID,
		Token:      enrollment.Token,
		CAPin:      enrollment.CAPin,
		ServerName: enrollment.ServerName,
		ExpiresAt:  enrollment.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *crudHandler) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	tokens, err := h.svc.ListEnrollmentTokens(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	out := make([]enrollmentTokenResponse, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, enrollmentTokenResponse{
			ID:        token.ID,
			NodeID:    token.NodeID,
			ExpiresAt: token.ExpiresAt.UTC().Format(time.RFC3339),
			UsedAt:    formatOptionalTime(token.UsedAt),
			CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *crudHandler) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r)
	if !ok {
		return
	}
	tokenID, err := strconv.ParseInt(chi.URLParam(r, "tokenID"), 10, 64)
	if err != nil || tokenID <= 0 {
		writeError(w, r, http.StatusBadRequest, codeBadRequest, "tokenID must be a positive integer")
		return
	}

	if err := h.svc.RevokeEnrollmentToken(r.Context(), actorFrom(r), nodeID, tokenID); err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- live connection state ---

type nodeConnectionResponse struct {
	NodeID    int64 `json:"node_id"`
	Connected bool  `json:"connected"`

	RemoteAddr     string `json:"remote_addr,omitempty"`
	ConnectedAt    string `json:"connected_at,omitempty"`
	LastHeartbeat  string `json:"last_heartbeat,omitempty"`
	AgentVersion   string `json:"agent_version,omitempty"`
	XrayVersion    string `json:"xray_version,omitempty"`
	AppliedVersion int64  `json:"applied_version,omitempty"`
	XrayRunning    bool   `json:"xray_running"`
}

// nodeConnection reports whether a node's control stream is open right now.
//
// Separate from the node's stored status because the two answer different questions.
// The column is a durable record written when a stream opens and closes; this is what
// the process currently holds. They disagree exactly when something has gone wrong,
// which is when an operator is looking.
func (h *crudHandler) nodeConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	// Confirms the node exists, so that a wrong id is a 404 rather than a plausible
	// "not connected".
	if _, err := h.svc.Queries().GetNode(r.Context(), id); err != nil {
		writeServiceError(w, r, h.logger, translateNotFound(err, "node"))
		return
	}

	if h.nodes == nil {
		// No gRPC server in this process, so there is nothing live to report.
		writeJSON(w, http.StatusOK, nodeConnectionResponse{NodeID: id})
		return
	}

	live, connected := h.nodes.Status(id)
	if !connected {
		writeJSON(w, http.StatusOK, nodeConnectionResponse{NodeID: id})
		return
	}

	writeJSON(w, http.StatusOK, nodeConnectionResponse{
		NodeID:         id,
		Connected:      true,
		RemoteAddr:     live.RemoteAddr,
		ConnectedAt:    live.ConnectedAt.UTC().Format(time.RFC3339),
		LastHeartbeat:  live.LastHeartbeat.UTC().Format(time.RFC3339),
		AgentVersion:   live.AgentVersion,
		XrayVersion:    live.XrayVersion,
		AppliedVersion: live.AppliedVersion,
		XrayRunning:    live.XrayRunning,
	})
}

// --- certificate authority ---

type caResponse struct {
	Pin            string `json:"pin"`
	ServerName     string `json:"server_name"`
	NotAfter       string `json:"not_after"`
	CertificatePEM string `json:"certificate_pem"`
}

// certificateAuthority returns the authority a node verifies the panel against.
//
// Public material: it is what nodes check the panel with, not what they authenticate
// with. It is exposed so that an operator provisioning a node by hand, or diagnosing a
// node that will not connect, can compare pins without reading the database.
func (h *crudHandler) certificateAuthority(w http.ResponseWriter, r *http.Request) {
	info, err := h.svc.CAInfo(r.Context())
	if err != nil {
		writeServiceError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, caResponse{
		Pin:            info.Pin,
		ServerName:     info.ServerName,
		NotAfter:       info.NotAfter.UTC().Format(time.RFC3339),
		CertificatePEM: info.CertificatePEM,
	})
}
