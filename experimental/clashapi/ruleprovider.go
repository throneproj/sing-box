package clashapi

import (
	"context"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleProviderRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders(router))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findRuleProviderByName(router))
		r.Get("/", getRuleProvider)
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := make(render.M)
		for _, ruleSet := range router.RuleSets() {
			providers[ruleSet.Name()] = ruleProviderInfo(ruleSet)
		}
		render.JSON(w, r, render.M{
			"providers": providers,
		})
	}
}

func getRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyProvider).(adapter.RuleSet)
	render.JSON(w, r, ruleProviderInfo(ruleSet))
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet, updatable := r.Context().Value(CtxKeyProvider).(adapter.UpdatableRuleSet)
	if !updatable {
		render.NoContent(w, r)
		return
	}
	err := ruleSet.Update(r.Context())
	if err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func findRuleProviderByName(router adapter.Router) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			ruleSet, exist := router.RuleSet(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProvider, ruleSet)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ruleProviderInfo(ruleSet adapter.RuleSet) render.M {
	vehicleType := "File"
	var updatedAt time.Time
	if updatable, isUpdatable := ruleSet.(adapter.UpdatableRuleSet); isUpdatable {
		vehicleType = "HTTP"
		updatedAt = updatable.LastUpdated()
	}
	return render.M{
		"name":        ruleSet.Name(),
		"type":        "Rule",
		"vehicleType": vehicleType,
		"behavior":    "Classical",
		"updatedAt":   updatedAt.Format(time.RFC3339),
	}
}
