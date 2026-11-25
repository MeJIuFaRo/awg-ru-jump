package strip_ipv6hint

import (
	"context"
	"errors"
	"net"
	"slices"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func init() {
	sequence.MustRegExecQuickSetup("strip_ipv6hint", func(_ sequence.BQ, args string) (any, error) {
		if args != "" {
			return nil, errors.New("strip_ipv6hint takes no arguments")
		}
		return stripIPv6Hint{}, nil
	})
}

type stripIPv6Hint struct{}

func (stripIPv6Hint) Exec(_ context.Context, qCtx *query_context.Context) error {
	response := qCtx.R()
	if response == nil {
		return nil
	}
	filtered := filterResponse(response)
	if filtered == response {
		return nil
	}
	// SetResponse extracts the upstream OPT from the response into the context.
	if opt := qCtx.UpstreamOpt(); opt != nil {
		filtered.Extra = append(filtered.Extra, opt)
	}
	qCtx.SetResponse(filtered)
	return nil
}

type rrset struct {
	name   string
	rrtype uint16
	class  uint16
}

type recordAction uint8

const (
	keepRecord recordAction = iota
	editRecord
	dropRecord
)

// miekg/dns decodes the obsolete A6 type as an RFC3597 record.
const typeA6 = 38

func filterResponse(response *dns.Msg) *dns.Msg {
	var filtered *dns.Msg
	var filteredSections [3]*[]dns.RR
	var changed map[rrset]struct{}
	for section, records := range messageSections(response) {
		for index, rr := range *records {
			action := addressRecordAction(rr)
			if action == keepRecord {
				continue
			}
			if filtered == nil {
				filtered = response.Copy()
				filteredSections = messageSections(filtered)
				changed = make(map[rrset]struct{})
			}
			header := rr.Header()
			changed[rrset{dns.CanonicalName(header.Name), header.Rrtype, header.Class}] = struct{}{}
			filteredRecords := *filteredSections[section]
			if action == dropRecord {
				filteredRecords[index] = nil
			} else {
				filteredRecords[index] = stripIPv6Fields(filteredRecords[index])
			}
		}
	}
	if filtered == nil {
		return response
	}
	for _, section := range filteredSections {
		*section = slices.DeleteFunc(*section, func(rr dns.RR) bool {
			if rr == nil {
				return true
			}
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				return false
			}
			_, touched := changed[rrset{dns.CanonicalName(sig.Hdr.Name), sig.TypeCovered, sig.Hdr.Class}]
			return touched
		})
	}
	filtered.AuthenticatedData = false
	return filtered
}

func messageSections(msg *dns.Msg) [3]*[]dns.RR {
	return [3]*[]dns.RR{&msg.Answer, &msg.Ns, &msg.Extra}
}

func addressRecordAction(rr dns.RR) recordAction {
	switch rr.Header().Rrtype {
	case dns.TypeAAAA, typeA6:
		return dropRecord
	}
	switch rr := rr.(type) {
	case *dns.IPSECKEY:
		if rr.GatewayType == dns.IPSECGatewayIPv6 {
			return dropRecord
		}
	case *dns.AMTRELAY:
		// AMTRELAY stores its discovery flag in the high bit of GatewayType.
		if rr.GatewayType&0x7f == dns.AMTRELAYIPv6 {
			return dropRecord
		}
	case *dns.APL:
		if slices.ContainsFunc(rr.Prefixes, isIPv6Prefix) {
			return editRecord
		}
	case *dns.SVCB, *dns.HTTPS:
		binding := serviceBinding(rr)
		hasHint, mandatory := ipv6HintStatus(binding.Value)
		if mandatory && binding.Priority != 0 {
			// Removing a mandatory key would invalidate the ServiceMode record.
			return dropRecord
		}
		if hasHint || mandatory {
			return editRecord
		}
	}
	return keepRecord
}

func stripIPv6Fields(rr dns.RR) dns.RR {
	if apl, ok := rr.(*dns.APL); ok {
		apl.Prefixes = slices.DeleteFunc(apl.Prefixes, isIPv6Prefix)
		if len(apl.Prefixes) == 0 {
			return nil
		}
		return rr
	}
	binding := serviceBinding(rr)
	binding.Value = slices.DeleteFunc(binding.Value, func(value dns.SVCBKeyValue) bool {
		// AliasMode ignores service parameters, so keep the alias target.
		if required, ok := value.(*dns.SVCBMandatory); ok && binding.Priority == 0 && slices.Contains(required.Code, dns.SVCB_IPV6HINT) {
			required.Code = slices.DeleteFunc(required.Code, isIPv6Hint)
			return len(required.Code) == 0
		}
		return value.Key() == dns.SVCB_IPV6HINT
	})
	return rr
}

func isIPv6Prefix(prefix dns.APLPrefix) bool {
	// APL uses the stored address width as its wire family, including mapped IPv6.
	return len(prefix.Network.IP) == net.IPv6len
}

func serviceBinding(rr dns.RR) *dns.SVCB {
	switch rr := rr.(type) {
	case *dns.HTTPS:
		return &rr.SVCB
	case *dns.SVCB:
		return rr
	default:
		return nil
	}
}

func ipv6HintStatus(values []dns.SVCBKeyValue) (hasHint, mandatory bool) {
	for _, value := range values {
		if value.Key() == dns.SVCB_IPV6HINT {
			hasHint = true
		}
		if required, ok := value.(*dns.SVCBMandatory); ok && slices.Contains(required.Code, dns.SVCB_IPV6HINT) {
			mandatory = true
		}
	}
	return hasHint, mandatory
}

func isIPv6Hint(key dns.SVCBKey) bool {
	return key == dns.SVCB_IPV6HINT
}
