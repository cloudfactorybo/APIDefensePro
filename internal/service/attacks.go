package service

import (
	"slices"
	"strings"

	"defensepro-api/internal/models"
)

// buildAttacks filtra el log de seguridad, calcula el resumen sobre todo lo
// filtrado y devuelve las entradas más recientes primero (AttackIndex es la
// clave creciente de la tabla), recortadas a f.Limit.
func buildAttacks(entries []models.Attack, f models.AttackFilter) *models.Attacks {
	risks := toSet(f.Risks)
	categories := toSet(f.Categories)
	actions := toSet(f.Actions)
	types := toSet(f.Types)
	policies := toSet(f.Policies)

	summary := models.AttackSummary{
		ByRisk:     map[string]int{},
		ByCategory: map[string]int{},
		ByAction:   map[string]int{},
		ByType:     map[string]int{},
	}

	selected := make([]models.Attack, 0, len(entries))
	for _, a := range entries {
		if !matches(risks, a.Risk) || !matches(categories, a.Category) || !matches(actions, a.Action) ||
			!matches(types, a.Type) || !matches(policies, a.PolicyName) {
			continue
		}
		selected = append(selected, a)
		summary.ByRisk[a.Risk]++
		summary.ByCategory[a.Category]++
		summary.ByAction[a.Action]++
		summary.ByType[a.Type]++
	}

	slices.SortStableFunc(selected, func(x, y models.Attack) int {
		switch {
		case x.Index > y.Index:
			return -1
		case x.Index < y.Index:
			return 1
		}
		return 0
	})

	summary.Total = len(selected)
	if f.Limit > 0 && len(selected) > f.Limit {
		selected = selected[:f.Limit]
	}
	summary.Returned = len(selected)

	return &models.Attacks{Summary: summary, Attacks: selected}
}

// toSet arma un set en minúsculas; nil si no hay valores (= sin filtro).
func toSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[strings.ToLower(v)] = true
	}
	return set
}

func matches(set map[string]bool, v string) bool {
	return set == nil || set[strings.ToLower(v)]
}
