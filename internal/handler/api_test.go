package handler

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseCSVParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?device=dp1,%20dp2&device=dp3&device=", nil)
	got := parseCSVParam(r, "device")
	if want := []string{"dp1", "dp2", "dp3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("parseCSVParam = %v, want %v", got, want)
	}
}

func TestParseAttackFilter(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?risk=high,medium&category=dos&policy=Web&type=started", nil)
	f, err := parseAttackFilter(r, defaultAttackLimit)
	if err != nil {
		t.Fatal(err)
	}
	if f.Limit != defaultAttackLimit || len(f.Risks) != 2 || f.Categories[0] != "dos" || f.Policies[0] != "Web" || f.Types[0] != "started" {
		t.Errorf("filtro = %+v", f)
	}

	f, err = parseAttackFilter(httptest.NewRequest("GET", "/x?limit=0", nil), defaultAttackLimit)
	if err != nil || f.Limit != 0 {
		t.Errorf("limit=0 → %+v, %v (debe significar sin límite)", f, err)
	}

	for _, bad := range []string{"-1", "abc", "10001"} {
		if _, err := parseAttackFilter(httptest.NewRequest("GET", "/x?limit="+bad, nil), defaultAttackLimit); err == nil {
			t.Errorf("limit=%s debería ser inválido", bad)
		}
	}
}
