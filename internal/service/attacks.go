package service

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"defensepro-api/internal/models"
)

// attackMatcher devuelve una función que indica si una entrada pasa el filtro.
func attackMatcher(f models.AttackFilter) func(models.Attack) bool {
	risks := toSet(f.Risks)
	categories := toSet(f.Categories)
	actions := toSet(f.Actions)
	types := toSet(f.Types)
	policies := toSet(f.Policies)
	return func(a models.Attack) bool {
		return matches(risks, a.Risk) && matches(categories, a.Category) && matches(actions, a.Action) &&
			matches(types, a.Type) && matches(policies, a.PolicyName)
	}
}

// buildAttacks filtra el log de seguridad, calcula el resumen sobre todo lo
// filtrado y devuelve las entradas más recientes primero (AttackIndex es la
// clave creciente de la tabla), recortadas a f.Limit.
func buildAttacks(entries []models.Attack, f models.AttackFilter) *models.Attacks {
	match := attackMatcher(f)
	summary := models.AttackSummary{
		ByRisk:     map[string]int{},
		ByCategory: map[string]int{},
		ByAction:   map[string]int{},
		ByType:     map[string]int{},
	}

	selected := make([]models.Attack, 0, len(entries))
	for _, a := range entries {
		if !match(a) {
			continue
		}
		selected = append(selected, a)
		summary.ByRisk[a.Risk]++
		summary.ByCategory[a.Category]++
		summary.ByAction[a.Action]++
		summary.ByType[a.Type]++
	}

	slices.SortStableFunc(selected, func(x, y models.Attack) int {
		return cmp.Compare(y.Index, x.Index)
	})

	summary.Total = len(selected)
	if f.Limit > 0 && len(selected) > f.Limit {
		selected = selected[:f.Limit]
	}
	summary.Returned = len(selected)

	return &models.Attacks{Summary: summary, Attacks: selected}
}

// analyzeAttacks agrega el log filtrado: totales, distribuciones y los top N
// por ataque, origen, destino, puerto destino y política. f.Limit se ignora.
func analyzeAttacks(entries []models.Attack, f models.AttackFilter, top int) models.AttackAnalytics {
	match := attackMatcher(f)
	out := models.AttackAnalytics{
		ByRisk:     map[string]int{},
		ByCategory: map[string]int{},
		ByAction:   map[string]int{},
		ByType:     map[string]int{},
		ByProtocol: map[string]int{},
	}
	names := map[string]*models.TopItem{}
	sources := map[string]*models.TopItem{}
	destinations := map[string]*models.TopItem{}
	ports := map[string]*models.TopItem{}
	policies := map[string]*models.TopItem{}

	var oldest, newest *models.Attack
	for i := range entries {
		a := &entries[i]
		if !match(*a) {
			continue
		}
		out.TotalEntries++
		out.TotalPackets += a.PacketCount
		out.TotalBytes += a.ByteCount
		out.ByRisk[a.Risk]++
		out.ByCategory[a.Category]++
		out.ByAction[a.Action]++
		out.ByType[a.Type]++
		out.ByProtocol[a.Protocol]++

		addTop(names, a.Name, a)
		addTop(sources, a.SourceAddress, a)
		addTop(destinations, a.DestinationAddress, a)
		addTop(policies, a.PolicyName, a)
		if a.DestinationPort > 0 {
			addTop(ports, a.Protocol+"/"+strconv.FormatInt(a.DestinationPort, 10), a)
		}

		if oldest == nil || a.Index < oldest.Index {
			oldest = a
		}
		if newest == nil || a.Index > newest.Index {
			newest = a
		}
	}
	if oldest != nil {
		out.OldestTime = oldest.Time
		out.NewestTime = newest.Time
	}

	out.TopAttacks = topN(names, top)
	out.TopSources = topN(sources, top)
	out.TopDestinations = topN(destinations, top)
	out.TopDestinationPorts = topN(ports, top)
	out.TopPolicies = topN(policies, top)
	return out
}

func addTop(m map[string]*models.TopItem, key string, a *models.Attack) {
	if key == "" {
		return
	}
	it, ok := m[key]
	if !ok {
		it = &models.TopItem{Key: key}
		m[key] = it
	}
	it.Count++
	it.Packets += a.PacketCount
	it.Bytes += a.ByteCount
}

// topN ordena por cantidad de eventos (desempate por clave) y corta en n.
func topN(m map[string]*models.TopItem, n int) []models.TopItem {
	out := make([]models.TopItem, 0, len(m))
	for _, it := range m {
		out = append(out, *it)
	}
	slices.SortFunc(out, func(a, b models.TopItem) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Key, b.Key))
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
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
