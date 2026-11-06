package gocap

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"maps"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// InstrumentationMeta holds the metadata needed to verify a client-side
// instrumentation result. It is encrypted and embedded in the JWT payload
// when instrumentation is enabled.
type InstrumentationMeta struct {
	ID                     string   `json:"id"`
	ExpectedVals           []int    `json:"expectedVals"`
	Vars                   []string `json:"vars"`
	BlockAutomatedBrowsers bool     `json:"blockAutomatedBrowsers"`
	Expires                int64    `json:"expires"`
}

// InstrumentationResult is the client-side instrumentation result payload,
// submitted back to the server for verification.
type InstrumentationResult struct {
	// I is the instrumentation challenge ID, matching InstrumentationMeta.ID.
	I string `json:"i"`
	// State maps each variable name to its computed client-side value.
	State map[string]int `json:"state"`
	// P is the browser probe vector collected by the instrumentation script.
	P ProbeVector `json:"p,omitempty"`
	// VP is the parent window viewport size ([width, height]).
	VP []float64 `json:"vp,omitempty"`
	// Ts is the client timestamp in Unix milliseconds.
	Ts int64 `json:"ts,omitzero"`
}

// InstrumentationOptions configures instrumentation generation behaviour.
type InstrumentationOptions struct {
	// BlockAutomatedBrowsers, when true, causes the server to reject
	// requests where the instrumentation was blocked.
	BlockAutomatedBrowsers bool
	// ObfuscationLevel selects the client script transformation level
	// (1-10, default 3). Levels 1-3 keep readable line breaks; levels 4-10
	// are compacted. The javascript-obfuscator transformations used by
	// capjs-core are not replicated, so this controls size/readability, not
	// obfuscation strength.
	ObfuscationLevel int
	// TTLMs is the instrumentation lifetime in milliseconds when calling
	// GenerateInstrumentation directly. Challenge generation always
	// overrides it with the challenge lifetime, matching capjs-core.
	TTLMs int64
}

func fastRnd(a, b int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(b-a+1)))
	if err != nil {
		return 0, err
	}

	return a + int(n.Int64()), nil
}

var (
	varLetters = "abcdefghijklmnopqrstuvwxyz"
	varChars   = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func rVar(length int) string {
	if length <= 0 {
		length = 8
	}

	b := make([]byte, length)
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(varLetters))))

	b[0] = varLetters[idx.Int64()]
	for i := 1; i < length; i++ {
		idx, _ = rand.Int(rand.Reader, big.NewInt(int64(len(varChars))))
		b[i] = varChars[idx.Int64()]
	}

	return string(b)
}

func toInt32(n int) int {
	return int(int32(n))
}

func rHex(length int) (string, error) {
	b := make([]byte, (length+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	s := ""
	for _, bb := range b {
		s += string("0123456789abcdef"[bb>>4])
		if len(s) >= length {
			break
		}

		s += string("0123456789abcdef"[bb&0xf])
	}

	return s[:length], nil
}

// instrumentationOp is one step of the client-side computation chain.
type instrumentationOp struct {
	op   int
	dest int
	src1 int
	src2 int
	src3 int
}

// instrumentationProgram is the server-side description of a generated
// instrumentation challenge. It is rendered into JavaScript for the client and
// evaluated in parallel to produce the expected values.
type instrumentationProgram struct {
	id                     string
	vars                   []string
	initVals               []int
	ops                    []instrumentationOp
	salts                  []int
	expected               []int
	correctKey             int
	badKey                 int
	blockAutomatedBrowsers bool
}

func generateInstrumentationProgram(opts InstrumentationOptions) (*instrumentationProgram, error) {
	id, err := rHex(32)
	if err != nil {
		return nil, err
	}

	vars := make([]string, 4)
	initVals := make([]int, 4)

	for i := range 4 {
		vars[i] = rVar(12)

		initVals[i], err = fastRnd(10, 250)
		if err != nil {
			return nil, err
		}
	}

	vals := make([]int, 4)
	copy(vals, initVals)

	correctKey, err := fastRnd(1000, 9000)
	if err != nil {
		return nil, err
	}

	badKey, err := fastRnd(1000, 9000)
	if err != nil {
		return nil, err
	}

	for badKey == correctKey {
		badKey, err = fastRnd(1000, 9000)
		if err != nil {
			return nil, err
		}
	}

	vals[0] = toInt32(vals[0] ^ correctKey)

	ops := make([]instrumentationOp, 0, 20)

	for range 20 {
		op, err := fastRnd(0, 5)
		if err != nil {
			return nil, err
		}

		dest, err := fastRnd(0, 3)
		if err != nil {
			return nil, err
		}

		src1, err := fastRnd(0, 3)
		if err != nil {
			return nil, err
		}

		src2, err := fastRnd(0, 3)
		if err != nil {
			return nil, err
		}

		src3, err := fastRnd(0, 3)
		if err != nil {
			return nil, err
		}

		ops = append(ops, instrumentationOp{op: op, dest: dest, src1: src1, src2: src2, src3: src3})

		vD := vals[dest]
		vS1 := vals[src1]
		vS2 := vals[src2]

		switch op {
		case 0:
			vals[dest] = toInt32(^(vD & vS1))
		case 1:
			vals[dest] = toInt32(vD ^ vS1)
		case 2:
			vals[dest] = toInt32(vD | vS1)
		case 3:
			vals[dest] = toInt32(vD & vS1)
		case 4:
			vals[dest] = toInt32((vS2 ^ vS1) | (vD ^ vS2))
		case 5:
			vals[dest] = toInt32(domSumMock(vals[src1], vals[src2], vals[src3]))
		}
	}

	salts := make([]int, 4)
	for i := range 4 {
		salts[i], err = fastRnd(100000, 999999)
		if err != nil {
			return nil, err
		}

		vals[i] = (((vals[i] ^ salts[i]) & 0x7fffffff) % 900000) + 100000
	}

	return &instrumentationProgram{
		id:                     id,
		vars:                   vars,
		initVals:               initVals,
		ops:                    ops,
		salts:                  salts,
		correctKey:             correctKey,
		badKey:                 badKey,
		blockAutomatedBrowsers: opts.BlockAutomatedBrowsers,
		expected:               vals,
	}, nil
}

// GenerateInstrumentation generates a complete, self-contained instrumentation
// challenge. It returns the metadata to be encrypted into the JWT and a
// base64-encoded, deflate-raw JavaScript bundle for the Cap widget.
func GenerateInstrumentation(opts InstrumentationOptions) (*InstrumentationMeta, string, error) {
	prog, err := generateInstrumentationProgram(opts)
	if err != nil {
		return nil, "", err
	}

	level := opts.ObfuscationLevel
	if level == 0 {
		level = 3
	}

	if level < 1 {
		level = 1
	}

	if level > 10 {
		level = 10
	}

	script := buildInstrumentationScript(prog, level)

	blob, err := compressInstrumentationScript(script)
	if err != nil {
		return nil, "", err
	}

	ttlMs := opts.TTLMs
	if ttlMs <= 0 {
		ttlMs = 5 * 60 * 1000
	}

	meta := &InstrumentationMeta{
		ID:                     prog.id,
		ExpectedVals:           prog.expected,
		Vars:                   prog.vars,
		BlockAutomatedBrowsers: prog.blockAutomatedBrowsers,
		Expires:                time.Now().UnixMilli() + ttlMs,
	}

	return meta, blob, nil
}

// compressInstrumentationScript deflates the script with raw DEFLATE and
// base64-encodes it, exactly like capjs-core's deflateRawSync(level: 1).
func compressInstrumentationScript(script string) (string, error) {
	var buf bytes.Buffer

	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return "", err
	}

	if _, err := w.Write([]byte(script)); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// buildInstrumentationScript renders the challenge program and probe code as
// JavaScript. Levels 1-3 keep readable line breaks; levels 4-10 are compacted.
// The javascript-obfuscator transformations used by capjs-core are not
// replicated; the wire format is identical, the obfuscation strength is not.
func buildInstrumentationScript(p *instrumentationProgram, level int) string {
	domName := rVar(8)
	sfName := rVar(8)
	natName := rVar(8)
	probeName := rVar(8)
	outName := rVar(8)
	idJSON, _ := json.Marshal(p.id)
	fontStacks, _ := json.Marshal(ProbeFontStacks)

	var b strings.Builder

	b.WriteString("(function(){\n")
	b.WriteString("function " + domName + "(x,y,z){var d=document.createElement('div');" +
		"d.style.display='none';document.body.appendChild(d);" +
		"function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');" +
		"p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}" +
		"function B(n,r,s){if(!n||n==r)return s%256;while(n.children.length>0)" +
		"n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}" +
		"var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}\n")
	b.WriteString("function " + natName + "(fn){try{return /\\{\\s*\\[native code\\]\\s*\\}/.test(Function.prototype.toString.call(fn))}catch(e){return true}}\n")
	b.WriteString("function go(){try{\n")
	b.WriteString("if(typeof window==='undefined'||typeof document==='undefined'||typeof navigator==='undefined')return;\n")
	b.WriteString("if(typeof HTMLElement!=='function'||typeof Window!=='function'||typeof Document!=='function'||typeof Navigator!=='function')return;\n")
	b.WriteString("if(!(navigator instanceof Navigator)||!(document instanceof Document)||!(window instanceof Window))return;\n")
	b.WriteString("if(globalThis!==window||window.self!==window||document.defaultView!==window)return;\n")
	b.WriteString("try{if(/(node:internal|moduleEvaluation|file:\\/\\/\\/)/.test((new Error()).stack||''))return}catch(e){}\n")

	if p.blockAutomatedBrowsers {
		b.WriteString("if(navigator.webdriver===true||/HeadlessChrome|PhantomJS|SlimerJS/i.test(navigator.userAgent||'')){parent.postMessage({type:'cap:instr',nonce:" + string(idJSON) + ",result:'',blocked:true,blockReason:'automated_browser'},'*');return;}\n")
	}

	for i, v := range p.vars {
		b.WriteString("var " + v + "=" + strconv.Itoa(p.initVals[i]) + ";")
	}

	b.WriteString("\n" + p.vars[0] + "=" + p.vars[0] + "^(navigator.userAgent?" + strconv.Itoa(p.correctKey) + ":" + strconv.Itoa(p.badKey) + ");\n")

	for _, op := range p.ops {
		vD := p.vars[op.dest]
		vS1 := p.vars[op.src1]
		vS2 := p.vars[op.src2]
		vS3 := p.vars[op.src3]

		switch op.op {
		case 0:
			b.WriteString(vD + "=~(" + vD + "&" + vS1 + ");\n")
		case 1:
			b.WriteString(vD + "=" + vD + "^" + vS1 + ";\n")
		case 2:
			b.WriteString(vD + "=" + vD + "|" + vS1 + ";\n")
		case 3:
			b.WriteString(vD + "=" + vD + "&" + vS1 + ";\n")
		case 4:
			b.WriteString(vD + "=(" + vS2 + "^" + vS1 + ")|(" + vD + "^" + vS2 + ");\n")
		case 5:
			b.WriteString(vD + "=" + domName + "(" + vS1 + "," + vS2 + "," + vS3 + ");\n")
		}
	}

	for i, v := range p.vars {
		b.WriteString(v + "=((" + v + "^" + strconv.Itoa(p.salts[i]) + ")&0x7FFFFFFF)%900000+100000;\n")
	}

	b.WriteString("var " + outName + "={};")

	for _, v := range p.vars {
		b.WriteString(outName + "[" + strconv.Quote(v) + "]=" + v + ";")
	}

	b.WriteString("\nvar " + probeName + "={};function " + sfName + "(k,f){try{" + probeName + "[k]=f()}catch(e){" + probeName + "[k]=null}}\n")
	b.WriteString(buildProbeJS(sfName, natName, string(fontStacks)))
	b.WriteString("parent.postMessage({type:'cap:instr',nonce:" + string(idJSON) + ",result:{i:" + string(idJSON) + ",state:" + outName + ",p:" + probeName + ",ts:Date.now()}},'*');\n")
	b.WriteString("}catch(e){}}\n")
	b.WriteString("if(document.readyState==='complete'){go()}else{window.addEventListener('load',go)}\n")
	b.WriteString("})();")

	script := b.String()
	if level <= 3 {
		return normalizeScriptWhitespace(script)
	}

	return compactScript(script)
}

func normalizeScriptWhitespace(script string) string {
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}

	return strings.Join(lines, "\n")
}

func compactScript(script string) string {
	return strings.ReplaceAll(normalizeScriptWhitespace(script), "\n", "")
}

func buildProbeJS(sfName, natName, fontStacks string) string {
	var b strings.Builder

	b.WriteString(sfName + "('ua',function(){return navigator.userAgent});\n")
	b.WriteString(sfName + "('productSub',function(){return navigator.productSub});\n")
	b.WriteString(sfName + "('webdriver',function(){return navigator.webdriver});\n")
	b.WriteString(sfName + "('oscpu',function(){return navigator.oscpu===undefined?'__undefined':navigator.oscpu});\n")
	b.WriteString(sfName + "('deviceMemory',function(){return navigator.deviceMemory});\n")
	b.WriteString(sfName + "('uaDataPresent',function(){return !!navigator.userAgentData});\n")
	b.WriteString(sfName + "('uaData',function(){var u=navigator.userAgentData;return u?{mobile:u.mobile,brands:(u.brands||[]).map(function(b){return b.brand+'/'+b.version})}:null});\n")
	b.WriteString(sfName + "('plugins',function(){return {length:navigator.plugins.length}});\n")
	b.WriteString(sfName + "('pdfViewerEnabled',function(){return navigator.pdfViewerEnabled});\n")
	b.WriteString(sfName + "('engine',function(){return {hasMozInnerScreenX:typeof window.mozInnerScreenX!=='undefined',hasChrome:typeof window.chrome!=='undefined'}});\n")
	b.WriteString(sfName + "('screen',function(){return {width:screen.width,height:screen.height}});\n")
	b.WriteString(sfName + "('outerWH',function(){return [outerWidth,outerHeight]});\n")
	b.WriteString(sfName + "('isExtended',function(){return screen.isExtended===undefined?null:screen.isExtended});\n")
	b.WriteString(sfName + "('fontWidths',function(){var sp=document.createElement('span');sp.style.cssText='position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap';sp.textContent='mmmmmmmmmmlli WwWwGg @#Xj';document.body.appendChild(sp);var st=" + fontStacks + ";var out=[];for(var i=0;i<st.length;i++){sp.style.fontFamily=st[i];out.push(Math.round(sp.getBoundingClientRect().width*100)/100)}sp.parentNode.removeChild(sp);return out});\n")
	b.WriteString(sfName + "('tamper',function(){return {getParameterWebGL:" + natName + "(WebGLRenderingContext.prototype.getParameter),toDataURL:" + natName + "(HTMLCanvasElement.prototype.toDataURL),getImageData:" + natName + "(CanvasRenderingContext2D.prototype.getImageData),permissionsQuery:navigator.permissions?" + natName + "(navigator.permissions.query):true,fnToString:" + natName + "(Function.prototype.toString)}});\n")

	return b.String()
}

// instrumentationVerification is the internal, detailed result of verifying
// an instrumentation response, including automation-detection signals.
type instrumentationVerification struct {
	Reason    string
	RiskFlags []string
	BlockedBy []string
	Valid     bool
}

// verifyInstrumentationResult performs state verification followed by the
// capjs-core probe/detection pipeline.
func verifyInstrumentationResult(
	meta *InstrumentationMeta,
	payload *InstrumentationResult,
) instrumentationVerification {
	if meta == nil {
		return instrumentationVerification{Reason: "missing_meta"}
	}

	if payload == nil {
		return instrumentationVerification{Reason: "missing_output"}
	}

	if payload.I != meta.ID {
		return instrumentationVerification{Reason: "id_mismatch"}
	}

	state := payload.State
	if state == nil {
		return instrumentationVerification{Reason: "invalid_state"}
	}

	if len(meta.Vars) == 0 || len(meta.ExpectedVals) == 0 {
		return instrumentationVerification{Reason: "invalid_meta"}
	}

	if len(meta.Vars) != len(meta.ExpectedVals) {
		return instrumentationVerification{Reason: "invalid_meta"}
	}

	for i, v := range meta.Vars {
		if state[v] != meta.ExpectedVals[i] {
			return instrumentationVerification{Reason: "failed_challenge"}
		}
	}

	probe := payload.P
	if probe != nil {
		if len(payload.VP) == 2 {
			vector := make(ProbeVector, len(probe)+1)
			maps.Copy(vector, probe)
			vector["innerWH"] = []any{payload.VP[0], payload.VP[1]}
			probe = vector
		}

		count := len(ProbeFontStacks)
		d := DetectAutomation(probe, &DetectOptions{FontStackCount: &count})

		if meta.BlockAutomatedBrowsers && !d.Pass {
			return instrumentationVerification{
				Reason:    "instr_automated_browser",
				BlockedBy: d.BlockedBy,
			}
		}

		return instrumentationVerification{Valid: true, RiskFlags: d.RiskFlags, BlockedBy: d.BlockedBy}
	}

	if meta.BlockAutomatedBrowsers {
		return instrumentationVerification{Reason: "instr_probe_missing"}
	}

	return instrumentationVerification{Valid: true, RiskFlags: []string{}}
}

// InstrumentationVerification is the detailed result of verifying an
// instrumentation response, including automation-detection signals.
type InstrumentationVerification struct {
	Reason    string   `json:"reason,omitempty"`
	RiskFlags []string `json:"riskFlags,omitempty"`
	BlockedBy []string `json:"blockedBy,omitempty"`
	Valid     bool     `json:"valid"`
}

// VerifyInstrumentationResultDetailed verifies an instrumentation response and
// returns the automation-detection signals alongside the validity decision.
func VerifyInstrumentationResultDetailed(
	meta *InstrumentationMeta,
	payload *InstrumentationResult,
) InstrumentationVerification {
	return InstrumentationVerification(verifyInstrumentationResult(meta, payload))
}

// VerifyInstrumentationResult checks whether the client's instrumentation
// response is valid. It verifies that the ID matches, that each variable has
// the expected value, and (when a probe is present) that the browser probe
// passes automation detection. The second return value is the failure reason.
func VerifyInstrumentationResult(
	meta *InstrumentationMeta,
	payload *InstrumentationResult,
) (bool, string) {
	vr := verifyInstrumentationResult(meta, payload)
	if vr.Valid {
		return true, ""
	}

	return false, vr.Reason
}

// instrSentinel maps an instrumentation failure reason to a sentinel error so
// callers can use errors.Is.
func instrSentinel(reason string) error {
	switch reason {
	case "instr_automated_browser":
		return ErrInstrAutomatedBrowser
	case "instr_probe_missing":
		return ErrInstrProbeMissing
	default:
		return ErrInstrFailed
	}
}

// domSumMock simulates the client-side DOM-based helper function for
// deterministic testability. It mirrors the widget's DOM manipulation
// without an actual browser environment.
func domSumMock(x, y, z int) int {
	type node struct {
		parentNode *node
		innerText  int
		isRoot     bool
	}

	root := &node{isRoot: true}
	buildChain := func(parent *node, val int) *node {
		cur := parent

		v := val
		for range 8 {
			child := &node{parentNode: cur, innerText: v}
			if v&1 == 0 {
				cur = child
			}

			v >>= 1
		}

		return cur
	}

	var walk func(n *node, rootRef *node, sum int) int

	walk = func(n *node, rootRef *node, sum int) int {
		if n == nil || n == rootRef {
			return sum % 256
		}

		return walk(n.parentNode, rootRef, sum+n.innerText)
	}

	return toInt32(walk(buildChain(buildChain(buildChain(root, x), y), z), root, 0))
}

// instrumentationMetaFromEncrypted decrypts and parses an encrypted
// instrumentation metadata blob from the JWT payload "ei" field.
func instrumentationMetaFromEncrypted(blob string, secret []byte) *InstrumentationMeta {
	data, ok := decryptGcmRaw(blob, secret)
	if !ok {
		return nil
	}

	var meta InstrumentationMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}

	return &meta
}

// encodeInstrumentationMeta encrypts instrumentation metadata for embedding
// in the JWT payload "ei" field.
func encodeInstrumentationMeta(meta *InstrumentationMeta, secret []byte) (string, error) {
	return encryptGcm(meta, secret)
}
