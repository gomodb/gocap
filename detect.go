package gocap

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
)

// ProbeVector is the browser probe vector collected by the instrumentation
// script. It mirrors the object sent by capjs-core in the `p` field.
//
// Values decoded from JSON use the usual Go representations: string, bool,
// float64, []any, map[string]any and nil (JSON null).
type ProbeVector map[string]any

// DetectionCheck is a single automation-detection check.
type DetectionCheck struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
	Passed bool   `json:"passed"`
	Gating bool   `json:"gating"`
}

// DetectionResult is the outcome of DetectAutomation.
type DetectionResult struct {
	Checks    []DetectionCheck `json:"checks"`
	BlockedBy []string         `json:"blockedBy"`
	RiskFlags []string         `json:"riskFlags"`
	Pass      bool             `json:"pass"`
}

// DetectOptions configures DetectAutomation.
type DetectOptions struct {
	// FontStackCount, when non-nil, enables the fontWidths length check.
	FontStackCount *int
}

// ProbeFontStacks is the font stack list embedded in the instrumentation
// script. Its length (17) must match the fontWidths probe array.
var ProbeFontStacks = []string{
	"sans-serif",
	"serif",
	"monospace",
	"Arial",
	"'Times New Roman'",
	"'Courier New'",
	"'Segoe UI'",
	"'SF Pro Text'",
	"'Helvetica Neue'",
	"'Ubuntu'",
	"'DejaVu Sans'",
	"'Roboto'",
	"Tahoma",
	"Calibri",
	"'Cantarell'",
	"'Liberation Sans'",
	"'Noto Sans'",
}

const (
	maxFontWidths    = 64
	maxTamperKeys    = 8
	maxTamperKeyLen  = 32
	maxDetailFields  = 6
	outerHeightSlack = 16
)

var (
	mobileUARe = regexp.MustCompile(
		`(?i)Android|iPhone|iPad|iPod|IEMobile|BlackBerry|` +
			`Mobile Safari|; Mobile|Silk|Kindle|Tizen|Opera Mini`,
	)
	headlessUARe = regexp.MustCompile(`(?i)headlesschrome`)
)

func numberValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

func isNum(v any) bool {
	f, ok := numberValue(v)

	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func isPlainObject(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case ProbeVector:
		return map[string]any(m), true
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	out := make(map[string]any, rv.Len())

	for _, k := range rv.MapKeys() {
		out[k.String()] = rv.MapIndex(k).Interface()
	}

	return out, true
}

func toAnySlice(v any) ([]any, bool) {
	if a, ok := v.([]any); ok {
		return a, true
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}

	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}

	return out, true
}

func isArray(v any) ([]any, bool) {
	return toAnySlice(v)
}

// probeCompleteness mirrors probeCompleteness in capjs-core's detect.js.
func probeCompleteness(s ProbeVector, fontStackCount *int) []string {
	if s == nil {
		return []string{"probe"}
	}

	type fieldType int

	const (
		ftString fieldType = iota
		ftBoolean
		ftObject
		ftArray
		ftNullableObject
		ftNullableBoolean
	)

	fields := []struct {
		name string
		kind fieldType
	}{
		{"ua", ftString},
		{"productSub", ftString},
		{"oscpu", ftString},
		{"uaDataPresent", ftBoolean},
		{"uaData", ftNullableObject},
		{"plugins", ftObject},
		{"engine", ftObject},
		{"screen", ftObject},
		{"outerWH", ftArray},
		{"isExtended", ftNullableBoolean},
		{"fontWidths", ftArray},
		{"tamper", ftNullableObject},
	}

	bad := make([]string, 0, len(fields))

	for _, f := range fields {
		v, present := s[f.name]
		if !present {
			bad = append(bad, f.name)

			continue
		}

		ok := false

		switch f.kind {
		case ftString:
			_, ok = v.(string)
		case ftBoolean:
			_, ok = v.(bool)
		case ftObject:
			_, ok = isPlainObject(v)
		case ftArray:
			_, ok = isArray(v)
		case ftNullableObject:
			ok = v == nil

			if !ok {
				_, ok = isPlainObject(v)
			}
		case ftNullableBoolean:
			ok = v == nil

			if !ok {
				_, ok = v.(bool)
			}
		}

		if !ok {
			bad = append(bad, f.name)
		}
	}

	if fontStackCount != nil {
		if widths, ok := isArray(s["fontWidths"]); ok && len(widths) != *fontStackCount {
			bad = append(bad, "fontWidths.length")
		}
	}

	return bad
}

// isMobileVector mirrors isMobileVector in capjs-core's detect.js.
func isMobileVector(s ProbeVector) bool {
	if uaData, ok := isPlainObject(s["uaData"]); ok {
		if mobile, ok := uaData["mobile"].(bool); ok && mobile {
			return true
		}
	}

	ua, _ := s["ua"].(string)

	return mobileUARe.MatchString(ua)
}

type geometry struct {
	count    int
	distinct int
	n        int
}

// geometryStats mirrors geometryStats in capjs-core's detect.js.
func geometryStats(fontWidths any) (geometry, bool) {
	arr, _ := isArray(fontWidths)
	if len(arr) > maxFontWidths {
		arr = arr[:maxFontWidths]
	}

	widths := make([]float64, 0, len(arr))

	for _, v := range arr {
		if f, ok := numberValue(v); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			widths = append(widths, f)
		}
	}

	if len(widths) < 6 {
		return geometry{}, false
	}

	count := 0
	distinct := make(map[float64]struct{}, len(widths))

	for _, w := range widths {
		if math.Trunc(w) == w {
			count++
			distinct[w] = struct{}{}
		}
	}

	return geometry{count: count, distinct: len(distinct), n: len(widths)}, true
}

// DetectAutomation mirrors detectAutomation in capjs-core's detect.js.
//
//nolint:gocyclo // faithful port of the upstream detector; splitting it makes it harder to compare.
func DetectAutomation(vector ProbeVector, opts *DetectOptions) DetectionResult {
	if vector == nil {
		return DetectionResult{
			Pass:      false,
			Checks:    []DetectionCheck{},
			BlockedBy: []string{"probe_missing"},
			RiskFlags: []string{},
		}
	}

	checks := make([]DetectionCheck, 0, 12)

	add := func(id string, passed bool, detail string, gating bool) {
		checks = append(checks, DetectionCheck{
			ID:     id,
			Passed: passed,
			Detail: detail,
			Gating: gating,
		})
	}

	var fontStackCount *int
	if opts != nil {
		fontStackCount = opts.FontStackCount
	}

	incomplete := probeCompleteness(vector, fontStackCount)

	detail := "all fields present"

	if len(incomplete) > 0 {
		shown := incomplete
		if len(shown) > maxDetailFields {
			shown = shown[:maxDetailFields]
		}

		detail = "missing or malformed: " + strings.Join(shown, ", ")
	}

	add("probe_incomplete", len(incomplete) == 0, detail, true)

	engine, _ := isPlainObject(vector["engine"])
	productSub, _ := vector["productSub"].(string)
	uaDataPresent, _ := vector["uaDataPresent"].(bool)
	oscpu, _ := vector["oscpu"].(string)

	gecko := false
	if hasMoz, ok := engine["hasMozInnerScreenX"].(bool); ok && hasMoz {
		gecko = true
	}

	if productSub == "20100101" && vector["uaDataPresent"] == false {
		gecko = true
	}

	if _, isString := vector["oscpu"].(string); isString && oscpu != "__undefined" {
		gecko = true
	}

	chromium := uaDataPresent

	if hasChrome, ok := engine["hasChrome"].(bool); ok && hasChrome {
		chromium = true
	}

	mobile := isMobileVector(vector)

	geo, hasGeo := geometryStats(vector["fontWidths"])
	quantized := hasGeo && geo.count >= 5 && geo.distinct >= 3

	geoDetail := "not measured"
	if hasGeo {
		geoDetail = fmt.Sprintf("%d/%d whole-px, %d distinct", geo.count, geo.n, geo.distinct)
	}

	add("geometry_quantized", !quantized, geoDetail, true)

	webdriverValue, webdriverPresent := vector["webdriver"]
	webdriver, webdriverBool := webdriverValue.(bool)

	add(
		"webdriver_true",
		!webdriverBool || !webdriver,
		fmt.Sprintf("webdriver=%v", webdriverValue),
		true,
	)

	stripped := chromium && !webdriverPresent

	strippedDetail := "not a chromium engine"
	if chromium {
		strippedDetail = "ok"
		if stripped {
			strippedDetail = "removed"
		}
	}

	add("webdriver_stripped", !stripped, strippedDetail, true)

	geckoContradiction := gecko &&
		(isNum(vector["deviceMemory"]) || vector["uaDataPresent"] == true)

	geckoDetail := "n/a"
	if gecko {
		geckoDetail = "gecko engine"
	}

	add("gecko_contradiction", !geckoContradiction, geckoDetail, true)

	screen, _ := isPlainObject(vector["screen"])
	outerWH, _ := isArray(vector["outerWH"])
	innerWH, _ := isArray(vector["innerWH"])

	singleMonitor := vector["isExtended"] == false

	outerTaller := false

	outerH, outerOK := numberValue(sliceAt(outerWH, 1))
	screenH, screenOK := numberValue(screen["height"])

	if outerOK && screenOK {
		outerTaller = outerH > screenH+outerHeightSlack
	}

	exceeds := outerTaller && singleMonitor

	windowDetail := "monitor layout unknown"
	if singleMonitor {
		windowDetail = "ok"
		if exceeds {
			windowDetail = fmt.Sprintf(
				"outerHeight %v > screen.height %v",
				outerH,
				screenH,
			)
		}
	}

	add("window_exceeds_screen", !exceeds, windowDetail, true)

	viewportIsScreen := false

	innerW, innerWOK := numberValue(sliceAt(innerWH, 0))
	innerH, innerHOK := numberValue(sliceAt(innerWH, 1))
	screenW, screenWOK := numberValue(screen["width"])

	if !mobile && innerWOK && innerHOK && screenWOK && screenOK && outerOK {
		viewportIsScreen = innerW == screenW && innerH == screenH && outerH > innerH
	}

	viewportDetail := "ok"
	if viewportIsScreen {
		viewportDetail = fmt.Sprintf(
			"viewport %vx%v == screen, window %v tall",
			innerW,
			innerH,
			outerH,
		)
	}

	add("viewport_override", !viewportIsScreen, viewportDetail, true)

	brands := ""

	if uaData, ok := isPlainObject(vector["uaData"]); ok {
		if arr, ok := toAnySlice(uaData["brands"]); ok {
			parts := make([]string, 0, len(arr))

			for _, b := range arr {
				if s, ok := b.(string); ok {
					parts = append(parts, s)
				}
			}

			brands = strings.Join(parts, " ")
		}
	}

	ua, _ := vector["ua"].(string)
	headless := headlessUARe.MatchString(brands) || headlessUARe.MatchString(ua)

	headlessDetail := "absent"
	if headless {
		headlessDetail = "HeadlessChrome present"
	}

	add("headless_token", !headless, headlessDetail, true)

	tamper, _ := isPlainObject(vector["tamper"])

	tampered := make([]string, 0, len(tamper))

	for k, v := range tamper {
		if b, ok := v.(bool); ok && !b {
			tampered = append(tampered, k)
		}
	}

	tamperDetail := "native"

	if len(tampered) > 0 {
		sortStrings(tampered)

		shown := tampered
		if len(shown) > maxTamperKeys {
			shown = shown[:maxTamperKeys]
		}

		keys := make([]string, 0, len(shown))

		for _, k := range shown {
			if len(k) > maxTamperKeyLen {
				k = k[:maxTamperKeyLen]
			}

			keys = append(keys, k)
		}

		tamperDetail = "JS-overridden: " + strings.Join(keys, ", ")
	}

	add("native_tamper", len(tampered) == 0, tamperDetail, false)

	blockedBy := make([]string, 0, len(checks))
	riskFlags := make([]string, 0, len(checks))

	for _, c := range checks {
		if c.Passed {
			continue
		}

		if c.Gating {
			blockedBy = append(blockedBy, c.ID)
		} else {
			riskFlags = append(riskFlags, c.ID)
		}
	}

	return DetectionResult{
		Pass:      len(blockedBy) == 0,
		Checks:    checks,
		BlockedBy: blockedBy,
		RiskFlags: riskFlags,
	}
}

// sortStrings is a tiny insertion sort to avoid pulling in sort for a handful
// of tamper keys.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// IsMobileVector reports whether the probe vector looks like a mobile client.
func IsMobileVector(s ProbeVector) bool {
	return isMobileVector(s)
}

// ProbeCompleteness returns the probe fields that are missing or malformed.
// When fontStackCount is non-nil, the fontWidths length is checked too.
func ProbeCompleteness(s ProbeVector, fontStackCount *int) []string {
	return probeCompleteness(s, fontStackCount)
}

// GeometryStat is the result of GeometryStats.
type GeometryStat struct {
	// Count is the number of whole-pixel widths.
	Count int `json:"count"`
	// Distinct is the number of distinct whole-pixel widths.
	Distinct int `json:"distinct"`
	// N is the number of numeric width samples.
	N int `json:"n"`
}

// GeometryStats summarizes font width samples. The bool is false when fewer
// than six numeric samples are available.
func GeometryStats(fontWidths []float64) (GeometryStat, bool) {
	values := make([]any, len(fontWidths))
	for i, w := range fontWidths {
		values[i] = w
	}

	g, ok := geometryStats(values)
	if !ok {
		return GeometryStat{}, false
	}

	return GeometryStat{Count: g.count, Distinct: g.distinct, N: g.n}, true
}

func sliceAt(values []any, index int) any {
	if index < 0 || index >= len(values) {
		return nil
	}

	return values[index]
}
