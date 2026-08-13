package scenario

type SuricataAlert struct {
	Timestamp string `json:"timestamp"`

	PcapCount int `json:"pcap_count"`

	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`

	DestIP   string `json:"dest_ip"`
	DestPort int    `json:"dest_port"`

	Proto    string `json:"proto"`
	AppProto string `json:"app_proto"`

	Action      string `json:"action"`
	SignatureID int    `json:"signature_id"`
	Signature   string `json:"signature"`
	Category    string `json:"category,omitempty"`
	Severity    int    `json:"severity"`

	DNSNames []string `json:"dns_names,omitempty"`
	DNSRCode string   `json:"dns_rcode,omitempty"`
}
