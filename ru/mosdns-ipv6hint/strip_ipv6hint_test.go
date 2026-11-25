package strip_ipv6hint

import (
	"bytes"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const signatureFields = " 13 2 60 20300101000000 20200101000000 12345 example. AQID"

func TestStripIPv6Hint(t *testing.T) {
	const (
		https           = "MiXeD.Example. 60 IN HTTPS 1 svc.example. mandatory=alpn alpn=h3 port=8443 ipv4hint=192.0.2.4 ech=AQID"
		secondHTTPS     = "MiXeD.Example. 60 IN HTTPS 2 svc.example. alpn=h2"
		unmodifiedHTTPS = "MiXeD.Example. 60 IN HTTPS 3 svc.example. alpn=h2"
		a               = "MiXeD.Example. 60 IN A 192.0.2.4"
		aaaa            = "svc.example. 60 IN AAAA 2001:db8::1"
		otherOwnerSig   = "different.example. 60 IN RRSIG HTTPS" + signatureFields
		otherClassSig   = "mixed.EXAMPLE. 60 CH RRSIG HTTPS" + signatureFields
		otherTypeSig    = "mixed.EXAMPLE. 60 IN RRSIG A" + signatureFields
		httpsSig        = "mixed.EXAMPLE. 60 IN RRSIG HTTPS" + signatureFields
		svcb            = "svc.example. 60 IN SVCB 2 . port=8443"
		droppedSVCB     = "Svc2.example. 60 IN SVCB 1 . mandatory=port,ipv6hint port=8443 ipv6hint=2001:db8::6"
	)
	query := new(dns.Msg).SetQuestion("mixed.example.", dns.TypeA)
	qCtx := query_context.NewContext(query)
	response := new(dns.Msg).SetReply(query)
	response.AuthenticatedData = true
	response.Answer = parseRecords(t,
		httpsSig,
		https+" ipv6hint=2001:db8::4",
		secondHTTPS+" ipv6hint=2001:db8::5",
		unmodifiedHTTPS,
		a, otherOwnerSig, otherClassSig, otherTypeSig,
	)
	response.Ns = parseRecords(t, svcb+" ipv6hint=2001:db8::7", "svc.example. 60 IN RRSIG SVCB"+signatureFields)
	response.Extra = parseRecords(t, droppedSVCB, "svc2.example. 60 IN RRSIG SVCB"+signatureFields, httpsSig, aaaa, a)
	response.SetEdns0(1232, true)
	upstreamOPT := response.IsEdns0()
	qCtx.SetResponse(response)
	before := packResponse(t, response)

	plugin, err := sequence.NewSequence(sequence.NewBQ(nil, zap.NewNop()), []sequence.RuleArgs{{Exec: "strip_ipv6hint"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := plugin.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	filtered := qCtx.R()
	if filtered == response || filtered.AuthenticatedData {
		t.Fatal("filtered response must use a copy with AD cleared")
	}
	if qCtx.UpstreamOpt() != upstreamOPT || filtered.IsEdns0() != nil {
		t.Fatal("upstream OPT must remain available through the query context")
	}
	assertRecords(t, filtered.Answer, https, secondHTTPS, unmodifiedHTTPS, a, otherOwnerSig, otherClassSig, otherTypeSig)
	assertRecords(t, filtered.Ns, svcb)
	assertRecords(t, filtered.Extra, a)
	if filtered.Answer[3].Header() == response.Answer[4].Header() {
		t.Fatal("the filtered response shares an RR header with the original")
	}
	if !bytes.Equal(before, packResponse(t, response)) {
		t.Fatal("the original response was modified")
	}
}

func TestStripIPv6HintNoChange(t *testing.T) {
	query := new(dns.Msg).SetQuestion("example.", dns.TypeHTTPS)
	qCtx := query_context.NewContext(query)
	plugin := stripIPv6Hint{}
	if err := plugin.Exec(t.Context(), qCtx); err != nil || qCtx.R() != nil {
		t.Fatalf("missing response changed, error = %v", err)
	}
	response := new(dns.Msg).SetReply(query)
	response.AuthenticatedData = true
	response.Answer = parseRecords(t,
		"example. 60 IN HTTPS 0 alias.example.",
		"example. 60 IN RRSIG HTTPS"+signatureFields,
	)
	qCtx.SetResponse(response)
	if err := plugin.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	if qCtx.R() != response || !response.AuthenticatedData || len(response.Answer) != 2 {
		t.Fatal("an unmodified response must retain AD and its signature")
	}
}

func TestStripIPv6HintPreservesAliasModeTarget(t *testing.T) {
	const (
		https = "example. 60 IN HTTPS 0 https-alias.example."
		svcb  = "example. 60 IN SVCB 0 svcb-alias.example."
	)
	response := &dns.Msg{
		Answer: parseRecords(t,
			https+" mandatory=ipv6hint ipv6hint=2001:db8::1",
			svcb+" mandatory=port,ipv6hint port=8443 ipv6hint=2001:db8::2",
		),
	}
	before := packResponse(t, response)
	filtered := filterResponse(response)
	assertRecords(t, filtered.Answer, https, svcb+" mandatory=port port=8443")
	if !bytes.Equal(before, packResponse(t, response)) {
		t.Fatal("the original alias records were modified")
	}
}

func TestFilterAAAARemovesIPv6FromAllSections(t *testing.T) {
	const (
		cname    = "www.example. 60 IN CNAME site.example."
		cnameSig = "www.example. 60 IN RRSIG CNAME" + signatureFields
		siteA    = "site.example. 60 IN A 192.0.2.1"
		siteASig = "site.example. 60 IN RRSIG A" + signatureFields
		ns       = "example. 60 IN NS ns.example."
		nsA      = "ns.example. 60 IN A 192.0.2.2"
	)
	query := new(dns.Msg).SetQuestion("www.example.", dns.TypeANY)
	response := new(dns.Msg).SetReply(query)
	response.AuthenticatedData = true
	response.Answer = parseRecords(t, cname, cnameSig, siteA, siteASig,
		"site.example. 60 IN AAAA 2001:db8::1", "SiTe.Example. 60 IN RRSIG AAAA"+signatureFields)
	response.Ns = parseRecords(t, ns, "ns.example. 60 IN AAAA 2001:db8::2")
	response.Extra = parseRecords(t, nsA,
		"other.example. 60 IN AAAA 2001:db8::3", "ns.example. 60 IN RRSIG AAAA"+signatureFields)

	filtered := filterResponse(response)
	if filtered.AuthenticatedData || filtered.Rcode != dns.RcodeSuccess || filtered.Question[0].Qtype != dns.TypeANY {
		t.Fatalf("unexpected filtered ANY response: %s", filtered)
	}
	assertRecords(t, filtered.Answer, cname, cnameSig, siteA, siteASig)
	assertRecords(t, filtered.Ns, ns)
	assertRecords(t, filtered.Extra, nsA)
}

func TestFilterIPv6FromOtherAddressRecords(t *testing.T) {
	const (
		keyIPv4    = "gateway.example. 60 IN IPSECKEY 10 1 2 192.0.2.1 AQID"
		keyHost    = "gateway.example. 60 IN IPSECKEY 10 3 2 host.example. AQID"
		relayIPv4  = "relay.example. 60 IN AMTRELAY 10 0 1 192.0.2.1"
		relayHost  = "relay.example. 60 IN AMTRELAY 10 0 3 host.example."
		apl        = "mixed.example. 60 IN APL"
		aplIPv4    = "v4.example. 60 IN APL 1:198.51.100.0/24"
		aplIPv4Sig = "v4.example. 60 IN RRSIG APL" + signatureFields
		txt        = `text.example. 60 IN TXT "2001:db8::1"`
		dnskey     = "example. 60 IN DNSKEY 256 3 13 AQID"
	)
	response := &dns.Msg{
		Answer: parseRecords(t,
			"gateway.example. 60 IN IPSECKEY 10 2 2 2001:db8::1 AQID", keyIPv4, keyHost,
			"gateway.example. 60 IN RRSIG IPSECKEY"+signatureFields,
			"relay.example. 60 IN AMTRELAY 10 1 2 2001:db8::2",
			"relay.example. 60 IN AMTRELAY 10 0 2 2001:db8::3", relayIPv4, relayHost,
			"relay.example. 60 IN RRSIG AMTRELAY"+signatureFields,
		),
		Ns: parseRecords(t,
			apl+" 1:192.0.2.0/24 !2:2001:db8::/32 !1:198.51.100.0/24 2:::ffff:203.0.113.1/128",
			"mixed.example. 60 IN RRSIG APL"+signatureFields,
			"v6.example. 60 IN APL 2:2001:db8::/32", "v6.example. 60 IN RRSIG APL"+signatureFields,
			aplIPv4, aplIPv4Sig,
		),
		Extra: parseRecords(t,
			`legacy.example. 60 IN TYPE38 \# 17 0020010DB8000000000000000000000001`,
			"legacy.example. 60 IN RRSIG TYPE38"+signatureFields,
			txt, dnskey,
		),
	}
	before := packResponse(t, response)
	filtered := filterResponse(response)
	assertRecords(t, filtered.Answer, keyIPv4, keyHost, relayIPv4, relayHost)
	assertRecords(t, filtered.Ns, apl+" 1:192.0.2.0/24 !1:198.51.100.0/24", aplIPv4, aplIPv4Sig)
	assertRecords(t, filtered.Extra, txt, dnskey)
	if !bytes.Equal(before, packResponse(t, response)) {
		t.Fatal("the original address records were modified")
	}
}

func parseRecords(t *testing.T, records ...string) []dns.RR {
	t.Helper()
	parsed := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, rr)
	}
	return parsed
}

func assertRecords(t *testing.T, records []dns.RR, expected ...string) {
	t.Helper()
	want := parseRecords(t, expected...)
	if len(records) != len(want) {
		t.Fatalf("got %d records (%v), want %d", len(records), records, len(want))
	}
	for i, rr := range records {
		if rr.String() != want[i].String() {
			t.Errorf("record %d = %s, want %s", i, rr, want[i])
		}
	}
}

func packResponse(t *testing.T, response *dns.Msg) []byte {
	t.Helper()
	data, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
