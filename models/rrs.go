package models

import (
	"encoding/binary"
	"net"
	"strings"
)

type RR_Header struct {
	Name     string
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
}

func (h *RR_Header) Header() *RR_Header { return h }

func (h *RR_Header) copyHeader() *RR_Header {
	r := new(RR_Header)
	r.Name = h.Name
	r.Name = strings.ToLower(Fqdn(r.Name))
	r.Rrtype = h.Rrtype
	r.Class = h.Class
	r.Ttl = h.Ttl
	r.Rdlength = h.Rdlength
	return r
}

func (h *RR_Header) len() int {
	l := len(h.Name) + 1
	l += 10 // rrtype(2) + class(2) + ttl(4) + rdlength(2)
	return l
}

func (hdr RR_Header) pack(msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	if off == len(msg) {
		return off, nil
	}

	off, err = PackDomainName(hdr.Name, msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}

	var rbuf Buffer
	rbuf.Data = msg
	rbuf.WritePos = off
	rbuf.WriteUint16BE(hdr.Rrtype)
	rbuf.WriteUint16BE(hdr.Class)
	rbuf.WriteUint32BE(hdr.Ttl)
	rbuf.WriteUint16BE(hdr.Rdlength)
	off = rbuf.WritePos
	return off, nil
}

func noRdata(h RR_Header) bool { return h.Rdlength == 0 }

type RR interface {
	Header() *RR_Header
	len() int
	pack([]byte, int, map[string]int, bool) (int, error)
}

////////////////////////////////////////////////////////////////////////////////////////

func unpackDataA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv4len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking a"}
	}
	a := append(make(net.IP, 0, net.IPv4len), msg[off:off+net.IPv4len]...)
	off += net.IPv4len
	return a, off, nil
}

func packDataA(a net.IP, msg []byte, off int) (int, error) {

	if off+net.IPv4len > len(msg) {
		return len(msg), &Error{err: "overflow packing a"}
	}
	switch len(a) {
	case net.IPv4len, net.IPv6len:
		copy(msg[off:], a.To4())
		off += net.IPv4len
	case 0:
		// Allowed, for dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing a"}
	}
	return off, nil
}

func unpackDataAAAA(msg []byte, off int) (net.IP, int, error) {
	if off+net.IPv6len > len(msg) {
		return nil, len(msg), &Error{err: "overflow unpacking aaaa"}
	}
	aaaa := append(make(net.IP, 0, net.IPv6len), msg[off:off+net.IPv6len]...)
	off += net.IPv6len
	return aaaa, off, nil
}

func packDataAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	if off+net.IPv6len > len(msg) {
		return len(msg), &Error{err: "overflow packing aaaa"}
	}

	switch len(aaaa) {
	case net.IPv6len:
		copy(msg[off:], aaaa)
		off += net.IPv6len
	case 0:
		// Allowed, dynamic updates.
	default:
		return len(msg), &Error{err: "overflow packing aaaa"}
	}
	return off, nil
}

func unpackA(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(A)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart
	rr.Hdr.Name = strings.ToLower(rr.Hdr.Name)
	rr.A, off, err = unpackDataA(msg, off)
	if err != nil {
		return rr, off, err
	}
	return rr, off, err
}

func unpackAAAA(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(AAAA)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart
	rr.Hdr.Name = strings.ToLower(rr.Hdr.Name)
	rr.AAAA, off, err = unpackDataAAAA(msg, off)
	if err != nil {
		return rr, off, err
	}
	return rr, off, err
}

func unpackMX(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(MX)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart

	var mbuf Buffer
	mbuf.Data = msg
	mbuf.ReadPos = off
	rr.Hdr.Name = strings.ToLower(rr.Hdr.Name)
	rr.Preference = mbuf.ReadUint16BE()
	off = mbuf.ReadPos
	if off == len(msg) {
		return rr, off, nil
	}
	rr.Mx, off = UnpackDomainName(msg, off)
	rr.Mx = strings.ToLower(rr.Mx)
	return rr, off, err
}

func unpackNS(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(NS)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart

	rr.Hdr.Name = strings.ToLower(Fqdn(rr.Hdr.Name))
	rr.Ns, off = UnpackDomainName(msg, off)
	rr.Ns = strings.ToLower(Fqdn(rr.Ns))
	return rr, off, err
}

func unpackCNAME(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(CNAME)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart
	rr.Hdr.Name = strings.ToLower(Fqdn(rr.Hdr.Name))
	rr.Target, off = UnpackDomainName(msg, off)
	rr.Target = strings.ToLower(Fqdn(rr.Target))
	return rr, off, err
}

func unpackUint32(msg []byte, off int) (i uint32, off1 int) {
	if off+4 > len(msg) {
		return 0, len(msg)
	}
	return binary.BigEndian.Uint32(msg[off:]), off + 4
}

func unpackSOA(h RR_Header, msg []byte, off int) (RR, int, error) {
	rr := new(SOA)
	rr.Hdr = h
	if noRdata(h) {
		return rr, off, nil
	}
	var err error
	rdStart := off
	_ = rdStart

	rr.Ns, off = UnpackDomainName(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Mbox, off = UnpackDomainName(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Serial, off = unpackUint32(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Refresh, off = unpackUint32(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Retry, off = unpackUint32(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Expire, off = unpackUint32(msg, off)

	if off == len(msg) {
		return rr, off, nil
	}
	rr.Minttl, off = unpackUint32(msg, off)

	return rr, off, err
}

func truncateMsgFromRdlength(msg []byte, off int, rdlength uint16) (truncmsg []byte, err error) {
	lenrd := off + int(rdlength)
	if lenrd > len(msg) {
		return msg, &Error{err: "overflowing header size"}
	}
	return msg[:lenrd], nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
type A struct {
	Hdr RR_Header
	A   net.IP `dns:"a"`
}

type AAAA struct {
	Hdr  RR_Header
	AAAA net.IP `dns:"aaaa"`
}

type NS struct {
	Hdr RR_Header
	Ns  string `dns:"cdomain-name"`
}

type MX struct {
	Hdr        RR_Header
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

type CNAME struct {
	Hdr    RR_Header
	Target string `dns:"cdomain-name"`
}

type SOA struct {
	Hdr     RR_Header
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

// Header() functions
func (rr *A) Header() *RR_Header     { return &rr.Hdr }
func (rr *AAAA) Header() *RR_Header  { return &rr.Hdr }
func (rr *MX) Header() *RR_Header    { return &rr.Hdr }
func (rr *CNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *NS) Header() *RR_Header    { return &rr.Hdr }
func (rr *SOA) Header() *RR_Header   { return &rr.Hdr }

/*
func (rr *A) String() *RR_Header    { return string("A") + rr.A.String() }
func (rr *AAAA) String() *RR_Header { return string("AAAA") + rr.AAAA.String() }
func (rr *MX) String() *RR_Header {
	return string("MX") + strconv.Itoa(int(rr.Preference)) + " " + rr.Mx
}
func (rr *CNAME) String() *RR_Header { return string("CNAME") + rr.Target }
func (rr *NS) String() string {
	return rr.Hdr.String() + sprintName(rr.Ns)
}
*/
func (rr *A) len() int {
	l := rr.Hdr.len()
	l += net.IPv4len // A
	return l
}
func (rr *AAAA) len() int {
	l := rr.Hdr.len()
	l += net.IPv6len // AAAA
	return l
}
func (rr *MX) len() int {
	l := rr.Hdr.len()
	l += 2 // Preference
	l += len(rr.Mx) + 1
	return l
}
func (rr *CNAME) len() int {
	l := rr.Hdr.len()
	l += len(rr.Target) + 1
	return l
}
func (rr *NS) len() int {
	l := rr.Hdr.len()
	l += len(rr.Ns) + 1
	return l
}
func (rr *SOA) len() int {
	l := rr.Hdr.len()
	l += len(rr.Ns) + 1
	l += len(rr.Mbox) + 1
	l += 4 // Serial
	l += 4 // Refresh
	l += 4 // Retry
	l += 4 // Expire
	l += 4 // Minttl
	return l
}
func (rr *A) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	rr.Header().Rdlength = 4
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	//headerEnd := off
	off, err = packDataA(rr.A, msg, off)
	if err != nil {
		return off, err
	}
	//rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}

func (rr *AAAA) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	rr.Header().Rdlength = 8
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	//headerEnd := off
	off, err = packDataAAAA(rr.AAAA, msg, off)
	if err != nil {
		return off, err
	}
	//rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}

func (rr *MX) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	headerEnd := off
	var buf Buffer
	buf.Data = msg
	buf.WritePos = off
	buf.WriteUint16BE(rr.Preference)
	off = buf.WritePos
	if err != nil {
		return off, err
	}
	off, err = PackDomainName(rr.Mx, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}

func (rr *CNAME) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	headerEnd := off
	off, err = PackDomainName(rr.Target, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}

func (rr *NS) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	headerEnd := off
	off, err = PackDomainName(rr.Ns, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}

func packUint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint32"}
	}

	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func (rr *SOA) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	off, err := rr.Hdr.pack(msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	headerEnd := off
	off, err = PackDomainName(rr.Ns, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = PackDomainName(rr.Mbox, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint32(rr.Serial, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(rr.Refresh, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(rr.Retry, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(rr.Expire, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(rr.Minttl, msg, off)
	if err != nil {
		return off, err
	}
	rr.Header().Rdlength = uint16(off - headerEnd)
	return off, nil
}
