package models

import (
	crand "crypto/rand"
	"encoding/binary"
	//"fmt"
	//"unsafe"
	"math/rand"
	"strconv"
)

func init() {
	// Initialize default math/rand source using crypto/rand to provide better
	// security without the performance trade-off.
	buf := make([]byte, 8)
	_, err := crand.Read(buf)
	if err != nil {
		// Failed to read from cryptographic source, fallback to default initial
		// seed (1) by returning early
		return
	}
	seed := binary.BigEndian.Uint64(buf)
	rand.Seed(int64(seed))
}

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

var (
	ErrAlg           error = &Error{err: "bad algorithm"}                  // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth          error = &Error{err: "bad authentication"}             // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf           error = &Error{err: "buffer size too small"}          // ErrBuf indicates that the buffer used it too small for the message.
	ErrConnEmpty     error = &Error{err: "conn has no connection"}         // ErrConnEmpty indicates a connection is being uses before it is initialized.
	ErrExtendedRcode error = &Error{err: "bad extended rcode"}             // ErrExtendedRcode ...
	ErrFqdn          error = &Error{err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrId            error = &Error{err: "id mismatch"}                    // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg        error = &Error{err: "bad key algorithm"}              // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey           error = &Error{err: "bad key"}
	ErrKeySize       error = &Error{err: "bad key size"}
	ErrNoSig         error = &Error{err: "no signature found"}
	ErrPrivKey       error = &Error{err: "bad private key"}
	ErrRcode         error = &Error{err: "bad rcode"}
	ErrRdata         error = &Error{err: "bad rdata"}
	ErrRRset         error = &Error{err: "bad rrset"}
	ErrSecret        error = &Error{err: "no secrets defined"}
	ErrShortRead     error = &Error{err: "short read"}
	ErrSig           error = &Error{err: "bad signature"}                      // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa           error = &Error{err: "no SOA"}                             // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime          error = &Error{err: "bad time"}                           // ErrTime indicates a timing error in TSIG authentication.
	ErrTruncated     error = &Error{err: "failed to unpack truncated message"} // ErrTruncated indicates that we failed to unpack a truncated message. We unpacked as much as we had so Msg can still be used, if desired.
)

// Id, by default, returns a 16 bits random number to be used as a
// message id. The random provided should be good enough. This being a
// variable the function can be reassigned to a custom function.
// For instance, to make it return a static value:
//
//	dns.Id = func() uint16 { return 3 }
var Id func() uint16 = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	id32 := rand.Uint32()
	return uint16(id32)
}

// Error represents a DNS error.
type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	return "dns: " + e.err
}

const (
	headerSize = 12

	_QR = 1 << 15
	_AA = 1 << 10
	_TC = 1 << 9
	_RD = 1 << 8
	_RA = 1 << 7
	_Z  = 1 << 6
	_AD = 1 << 5
	_CD = 1 << 4
)

const (
	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// valid Question.Qtype only
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeReserved uint16 = 65535

	// valid Question.Qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes.
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
	RcodeYXDomain       = 6
	RcodeYXRrset        = 7
	RcodeNXRrset        = 8
	RcodeNotAuth        = 9
	RcodeNotZone        = 10
	RcodeBadSig         = 16 // TSIG
	RcodeBadVers        = 16 // EDNS0
	RcodeBadKey         = 17
	RcodeBadTime        = 18
	RcodeBadMode        = 19 // TKEY
	RcodeBadName        = 20
	RcodeBadAlg         = 21
	RcodeBadTrunc       = 22 // TSIG
	RcodeBadCookie      = 23 // DNS Cookies

	// Message Opcodes. There is no 3.
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
	OpcodeNotify = 4
	OpcodeUpdate = 5
)

type Header struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

func (dh *Header) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	var buf Buffer
	buf.Data = msg
	buf.WritePos = off
	buf.WriteUint16BE(dh.Id)
	buf.WriteUint16BE(dh.Bits)
	buf.WriteUint16BE(dh.Qdcount)
	buf.WriteUint16BE(dh.Ancount)
	buf.WriteUint16BE(dh.Nscount)
	buf.WriteUint16BE(dh.Arcount)
	off = buf.WritePos
	return off, nil
}

type MsgHdr struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func (q *Question) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error) {
	off, err := PackDomainName(q.Name, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	var buf Buffer
	buf.Data = msg
	buf.WritePos = off
	buf.WriteUint16BE(q.Qtype)
	buf.WriteUint16BE(q.Qclass)
	off = buf.WritePos
	return off, nil
}

func (q *Question) len() int {
	return len(q.Name) + 1 + 2 + 2
}

type Msg struct {
	MsgHdr
	Compress bool
	Question []Question
	Answer   []RR // Holds the RR(s) of the answer section.
	Ns       []RR // Holds the RR(s) of the authority section.
	Extra    []RR // Holds the RR(s) of the additional section.
}

func IsFqdn(s string) bool {
	l := len(s)
	if l == 0 {
		return false
	}
	return s[l-1] == '.'
}

func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

func PackDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	off1, _, err = packDomainName(s, msg, off, compression, compress)
	return
}

func packDomainName(s string, msg []byte, off int, compression map[string]int, compress bool) (off1 int, labels int, err error) {
	// special case if msg == nil
	lenmsg := 256
	if msg != nil {
		lenmsg = len(msg)
	}
	ls := len(s)
	if ls == 0 {
		return off, 0, nil
	}
	// If not fully qualified, error out, but only if msg == nil #ugly
	switch {
	case msg == nil:
		if s[ls-1] != '.' {
			s += "."
			ls++
		}
	case msg != nil:
		if s[ls-1] != '.' {
			return lenmsg, 0, ErrFqdn
		}
	}
	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	nameoffset := -1
	pointer := -1
	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	bs := []byte(s)
	roBs, bsFresh, escapedDot := s, true, false
	for i := 0; i < ls; i++ {

		if bs[i] == '.' {
			if i > 0 && bs[i-1] == '.' && !escapedDot {
				// two dots back to back is not legal
				return lenmsg, labels, ErrRdata
			}
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return lenmsg, labels, ErrRdata
			}
			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1 > lenmsg {
				return lenmsg, labels, ErrBuf
			}
			if msg != nil {
				msg[off] = byte(i - begin)
			}
			offset := off
			off++
			for j := begin; j < i; j++ {
				if off+1 > lenmsg {
					return lenmsg, labels, ErrBuf
				}
				if msg != nil {
					msg[off] = bs[j]
				}
				off++
			}
			if compress && !bsFresh {
				roBs = string(bs)
				bsFresh = true
			}
			// Don't try to compress '.'
			if compress && roBs[begin:] != "." {
				if p, ok := compression[roBs[begin:]]; !ok {
					// Only offsets smaller than this can be used.
					if offset < maxCompressionOffset {
						compression[roBs[begin:]] = offset
					}
				} else {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're allowed to compress this dname
					if pointer == -1 && compress {
						pointer = p         // Where to point to
						nameoffset = offset // Where to point from
						break
					}
				}
			}
			labels++
			begin = i + 1
		}
		escapedDot = false
	}
	// Root label is special
	if len(bs) == 1 && bs[0] == '.' {
		return off, labels, nil
	}
	// If we did compression and we find something add the pointer here
	if pointer != -1 {
		// We have two bytes (14 bits) to put the pointer in
		// if msg == nil, we will never do compression
		binary.BigEndian.PutUint16(msg[nameoffset:], uint16(pointer^0xC000))
		off = nameoffset + 1
		goto End
	}
	if msg != nil && off < len(msg) {
		msg[off] = 0
	}
End:
	off++
	return off, labels, nil
}

func UnpackDomainName(msg []byte, off int) (string, int) {
	s := make([]byte, 0, 64)
	off1 := 0
	lenmsg := len(msg)
	ptr := 0
Loop:
	for {
		//i := int(1)
		if off >= lenmsg {
			return "", lenmsg
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of name
				break Loop
			}
			// literal string
			if off+c > lenmsg {
				return "", lenmsg
			}
			for j := off; j < off+c; j++ {
				switch b := msg[j]; b {
				case '.', '(', ')', ';', ' ', '@':
					fallthrough
				case '"', '\\':
					s = append(s, '\\', b)
				case '\t':
					s = append(s, '\\', 't')
				case '\r':
					s = append(s, '\\', 'r')
				default:
					if b < 32 || b >= 127 { // unprintable use \DDD
						var buf [3]byte
						bufs := strconv.AppendInt(buf[:0], int64(b), 10)
						s = append(s, '\\')
						for i := 0; i < 3-len(bufs); i++ {
							s = append(s, '0')
						}
						for _, r := range bufs {
							s = append(s, r)
						}
					} else {
						s = append(s, b)
					}
				}
			}
			s = append(s, '.')
			off += c
		case 0xC0:
			if off >= lenmsg {
				return "", lenmsg
			}
			c1 := msg[off]
			off++
			if ptr == 0 {
				off1 = off
			}
			if ptr++; ptr > 10 {
				return "", lenmsg
			}
			off = (c^0xC0)<<8 | int(c1)
		default:
			// 0x80 and 0x40 are reserved
			return "", lenmsg
		}
	}
	if ptr == 0 {
		off1 = off
	}
	if len(s) == 0 {
		s = []byte(".")
	}
	return string(s), off1
}

func unpackMsgHdr(msg []byte) (Header, int) {
	var dh Header
	var hbuf Buffer
	hbuf.Data = msg
	dh.Id = hbuf.ReadUint16BE()
	dh.Bits = hbuf.ReadUint16BE()
	dh.Qdcount = hbuf.ReadUint16BE()
	dh.Ancount = hbuf.ReadUint16BE()
	dh.Nscount = hbuf.ReadUint16BE()
	dh.Arcount = hbuf.ReadUint16BE()

	return dh, hbuf.ReadPos
}

func unpackRRHeader(msg []byte, off int) (rr RR_Header, off1 int, truncmsg []byte, err error) {
	hdr := RR_Header{}
	if off == len(msg) {
		return hdr, off, msg, nil
	}

	hdr.Name, off = UnpackDomainName(msg, off)
	var rbuf Buffer
	rbuf.Data = msg
	rbuf.ReadPos = off
	hdr.Rrtype = rbuf.ReadUint16BE()
	hdr.Class = rbuf.ReadUint16BE()
	hdr.Ttl = rbuf.ReadUint32BE()
	hdr.Rdlength = rbuf.ReadUint16BE()
	off = rbuf.ReadPos
	msg, err = truncateMsgFromRdlength(msg, off, hdr.Rdlength)
	return hdr, off, msg, err
}

func unpackQuestion(msg []byte, off int) (Question, int) {
	var (
		q Question
	)
	q.Name, off = UnpackDomainName(msg, off)

	if off == len(msg) {
		return q, off
	}
	var mbuf Buffer
	mbuf.Data = msg
	mbuf.ReadPos = off
	q.Qtype = mbuf.ReadUint16BE()
	off = mbuf.ReadPos

	if off == len(msg) {
		return q, off
	}

	mbuf.Data = msg
	mbuf.ReadPos = off
	q.Qclass = mbuf.ReadUint16BE()
	off = mbuf.ReadPos

	return q, off
}

func rawSetRdlength(msg []byte, off, end int) bool {
	l := len(msg)
Loop:
	for {
		if off+1 > l {
			return false
		}
		c := int(msg[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// End of the domainname
				break Loop
			}
			if off+c > l {
				return false
			}
			off += c

		case 0xC0:
			// pointer, next byte included, ends domainname
			off++
			break Loop
		}
	}
	// The domainname has been seen, we at the start of the fixed part in the header.
	// Type is 2 bytes, class is 2 bytes, ttl 4 and then 2 bytes for the length.
	off += 2 + 2 + 4
	if off+2 > l {
		return false
	}
	//off+1 is the end of the header, 'end' is the end of the rr
	//so 'end' - 'off+2' is the length of the rdata
	rdatalen := end - (off + 2)
	if rdatalen > 0xFFFF {
		return false
	}
	binary.BigEndian.PutUint16(msg[off:], uint16(rdatalen))
	return true
}

func PackRR(rr RR, msg []byte, off int, compression map[string]int, compress bool) (off1 int, err error) {
	if rr == nil {
		return len(msg), &Error{err: "nil rr"}
	}

	off1, err = rr.pack(msg, off, compression, compress)
	if err != nil {
		return len(msg), err
	}
	// TODO(miek): Not sure if this is needed? If removed we can remove rawmsg.go as well.
	rawSetRdlength(msg, off, off1)
	//return off1, nil
	//}
	return off1, err
}

func UnpackRR(msg []byte, off int) (rr RR, off1 int) {
	h, off, msg, _ := unpackRRHeader(msg, off)
	end := off + int(h.Rdlength)
	if h.Rrtype == TypeA {
		rr, off, _ = unpackA(h, msg, off)
	} else if h.Rrtype == TypeAAAA {
		rr, off, _ = unpackAAAA(h, msg, off)
	} else if h.Rrtype == TypeMX {
		rr, off, _ = unpackMX(h, msg, off)
	} else if h.Rrtype == TypeNS {
		rr, off, _ = unpackNS(h, msg, off)
	} else if h.Rrtype == TypeCNAME {
		rr, off, _ = unpackCNAME(h, msg, off)
	} else if h.Rrtype == TypeSOA {
		rr, off, _ = unpackSOA(h, msg, off)
	} else {
		//fmt.Println("UnpackRR type not found : ", h.Rrtype)
		//panic(nil)
		return rr, -1
	}
	if off != end {
		return &h, end
	}
	return rr, off
}

func unpackRRslice(l int, msg []byte, off int) (dst1 []RR, off1 int) {
	var r RR

	dst := make([]RR, 0, l)
	for i := 0; i < l; i++ {
		off1 := off
		r, off = UnpackRR(msg, off)
		if off == -1 {
			return dst, -1
		}
		if off1 == off {
			l = i
			break
		}
		dst = append(dst, r)
	}

	return dst, off
}

func (dns *Msg) Unpack(msg []byte) (err error) {

	/*defer func() {
		if rc := recover(); rc != nil {
			Log.Error("Unpack Recover:%v", rc)
		}
	}()*/

	dh, off := unpackMsgHdr(msg)

	dns.Id = dh.Id
	dns.Response = (dh.Bits & _QR) != 0
	dns.Opcode = int(dh.Bits>>11) & 0xF
	dns.Authoritative = (dh.Bits & _AA) != 0
	dns.Truncated = (dh.Bits & _TC) != 0
	dns.RecursionDesired = (dh.Bits & _RD) != 0
	dns.RecursionAvailable = (dh.Bits & _RA) != 0
	dns.Zero = (dh.Bits & _Z) != 0
	dns.AuthenticatedData = (dh.Bits & _AD) != 0
	dns.CheckingDisabled = (dh.Bits & _CD) != 0
	dns.Rcode = int(dh.Bits & 0xF)

	// Optimistically use the count given to us in the header
	dns.Question = make([]Question, 0, int(dh.Qdcount))

	for i := 0; i < int(dh.Qdcount); i++ {
		off1 := off
		var q Question
		q, off = unpackQuestion(msg, off)

		if off1 == off { // Offset does not increase anymore, dh.Qdcount is a lie!
			dh.Qdcount = uint16(i)
			break
		}
		dns.Question = append(dns.Question, q)
	}

	if dh.Ancount > 0 {
		dns.Answer, off = unpackRRslice(int(dh.Ancount), msg, off)
		if off == -1 {
			//fmt.Printf("%+v\n", dh)
			//fmt.Printf("%+v\n", dns)
			return ErrRdata
		}
	}

	// The header counts might have been wrong so we need to update it
	//dh.Ancount = uint16(len(dns.Answer))
	if dh.Nscount > 0 {
		dns.Ns, off = unpackRRslice(int(dh.Nscount), msg, off)
		if off == -1 {
			//fmt.Printf("%+v\n", dh)
			//fmt.Printf("%+v\n", dns)
			return ErrRdata
		}
	}

	// The header counts might have been wrong so we need to update it
	//dh.Nscount = uint16(len(dns.Ns))
	if dh.Arcount > 0 {
		dns.Extra, off = unpackRRslice(int(dh.Arcount), msg, off)
		if off == -1 {
			//fmt.Printf("%+v\n", dh)
			//fmt.Printf("%+v\n", dns)
			return ErrRdata
		}
	}

	// The header counts might have been wrong so we need to update it
	//dh.Arcount = uint16(len(dns.Extra))

	if off != len(msg) {
		// TODO(miek) make this an error?
		// use PackOpt to let people tell how detailed the error reporting should be?
		// println("dns: extra bytes in dns packet", off, "<", len(msg))
	} else if dns.Truncated {
		// Whether we ran into a an error or not, we want to return that it
		// was truncated
		//err = ErrTruncated
	}
	//fmt.Println(dns, "   ", off, len(msg))
	return err
}

func (dns *Msg) SetQuestion(z string, t uint16) *Msg {
	dns.Id = Id()
	//dns.RecursionDesired = true
	dns.Question = make([]Question, 1)
	dns.Question[0] = Question{z, t, ClassINET}
	return dns
}

func (dns *Msg) SetReply(request *Msg) *Msg {
	dns.Id = request.Id
	dns.RecursionDesired = request.RecursionDesired // Copy rd bit
	dns.Response = true
	dns.RecursionDesired = true
	dns.Opcode = OpcodeQuery
	dns.Rcode = RcodeSuccess
	if len(request.Question) > 0 {
		dns.Question = make([]Question, 1)
		dns.Question[0] = request.Question[0]
	}

	return dns
}

func (dns *Msg) PackBuffer(buf []byte) (msg []byte, err error) {
	// We use a similar function in tsig.go's stripTsig.
	var (
		dh          Header
		compression map[string]int
	)

	if dns.Compress {
		compression = make(map[string]int) // Compression pointer mappings
	}

	if dns.Rcode < 0 || dns.Rcode > 0xFFF {
		return nil, ErrRcode
	}
	/*if dns.Rcode > 0xF {
		// Regular RCODE field is 4 bits
		opt := dns.IsEdns0()
		if opt == nil {
			return nil, ErrExtendedRcode
		}
		opt.SetExtendedRcode(uint8(dns.Rcode >> 4))
		dns.Rcode &= 0xF
	}*/

	// Convert convenient Msg into wire-like Header.
	dh.Id = dns.Id
	dh.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode)
	if dns.Response {
		dh.Bits |= _QR
	}
	if dns.Authoritative {
		dh.Bits |= _AA
	}
	if dns.Truncated {
		dh.Bits |= _TC
	}
	if dns.RecursionDesired {
		dh.Bits |= _RD
	}
	if dns.RecursionAvailable {
		dh.Bits |= _RA
	}
	if dns.Zero {
		dh.Bits |= _Z
	}
	if dns.AuthenticatedData {
		dh.Bits |= _AD
	}
	if dns.CheckingDisabled {
		dh.Bits |= _CD
	}

	// Prepare variable sized arrays.
	question := dns.Question
	answer := dns.Answer
	ns := dns.Ns
	extra := dns.Extra

	dh.Qdcount = uint16(len(question))
	dh.Ancount = uint16(len(answer))
	dh.Nscount = uint16(len(ns))
	dh.Arcount = uint16(len(extra))

	// We need the uncompressed length here, because we first pack it and then compress it.
	msg = buf
	compress := dns.Compress
	dns.Compress = false
	if packLen := dns.Len() + 1; len(msg) < packLen {
		msg = make([]byte, packLen)
	}
	dns.Compress = compress

	// Pack it in: header and then the pieces.
	off := 0
	off, err = dh.pack(msg, off, compression, dns.Compress)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(question); i++ {
		off, err = question[i].pack(msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(answer); i++ {
		off, err = PackRR(answer[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(ns); i++ {
		off, err = PackRR(ns[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < len(extra); i++ {
		off, err = PackRR(extra[i], msg, off, compression, dns.Compress)
		if err != nil {
			return nil, err
		}
	}
	return msg[:off], nil
}

// Len returns the message length when in (un)compressed wire format.
// If dns.Compress is true compression it is taken into account. Len()
// is provided to be a faster way to get the size of the resulting packet,
// than packing it, measuring the size and discarding the buffer.
func (dns *Msg) Len() int {
	// We always return one more than needed.
	l := 12 // Message header is always 12 bytes
	var compression map[string]int
	if dns.Compress {
		compression = make(map[string]int)
	}
	for i := 0; i < len(dns.Question); i++ {
		l += dns.Question[i].len()
		if dns.Compress {
			compressionLenHelper(compression, dns.Question[i].Name)
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		if dns.Answer[i] == nil {
			continue
		}
		l += dns.Answer[i].len()
		if dns.Compress {
			k, ok := compressionLenSearch(compression, dns.Answer[i].Header().Name)
			if ok {
				l += 1 - k
			}
			compressionLenHelper(compression, dns.Answer[i].Header().Name)
			k, ok = compressionLenSearchType(compression, dns.Answer[i])
			if ok {
				l += 1 - k
			}
			compressionLenHelperType(compression, dns.Answer[i])
		}
	}
	for i := 0; i < len(dns.Ns); i++ {
		if dns.Ns[i] == nil {
			continue
		}
		l += dns.Ns[i].len()
		if dns.Compress {
			k, ok := compressionLenSearch(compression, dns.Ns[i].Header().Name)
			if ok {
				l += 1 - k
			}
			compressionLenHelper(compression, dns.Ns[i].Header().Name)
			k, ok = compressionLenSearchType(compression, dns.Ns[i])
			if ok {
				l += 1 - k
			}
			compressionLenHelperType(compression, dns.Ns[i])
		}
	}
	for i := 0; i < len(dns.Extra); i++ {
		if dns.Extra[i] == nil {
			continue
		}
		l += dns.Extra[i].len()
		if dns.Compress {
			k, ok := compressionLenSearch(compression, dns.Extra[i].Header().Name)
			if ok {
				l += 1 - k
			}
			compressionLenHelper(compression, dns.Extra[i].Header().Name)
			k, ok = compressionLenSearchType(compression, dns.Extra[i])
			if ok {
				l += 1 - k
			}
			compressionLenHelperType(compression, dns.Extra[i])
		}
	}
	return l
}

// Put the parts of the name in the compression map.
func compressionLenHelper(c map[string]int, s string) {
	pref := ""
	lbs := Split(s)
	for j := len(lbs) - 1; j >= 0; j-- {
		pref = s[lbs[j]:]
		if _, ok := c[pref]; !ok {
			c[pref] = len(pref)
		}
	}
}

// Look for each part in the compression map and returns its length,
// keep on searching so we get the longest match.
func compressionLenSearch(c map[string]int, s string) (int, bool) {
	off := 0
	end := false
	if s == "" { // don't bork on bogus data
		return 0, false
	}
	for {
		if _, ok := c[s[off:]]; ok {
			return len(s[off:]), true
		}
		if end {
			break
		}
		off, end = NextLabel(s, off)
	}
	return 0, false
}

// TODO(miek): should add all types, because the all can be *used* for compression. Autogenerate from msg_generate and put in zmsg.go
func compressionLenHelperType(c map[string]int, r RR) {
	switch x := r.(type) {
	case *NS:
		compressionLenHelper(c, x.Ns)
	case *MX:
		compressionLenHelper(c, x.Mx)
	case *CNAME:
		compressionLenHelper(c, x.Target)
		/*/case *PTR:
			compressionLenHelper(c, x.Ptr)
		case *SOA:
			compressionLenHelper(c, x.Ns)
			compressionLenHelper(c, x.Mbox)
		case *MB:
			compressionLenHelper(c, x.Mb)
		case *MG:
			compressionLenHelper(c, x.Mg)
		case *MR:
			compressionLenHelper(c, x.Mr)
		case *MF:
			compressionLenHelper(c, x.Mf)
		case *MD:
			compressionLenHelper(c, x.Md)
		case *RT:
			compressionLenHelper(c, x.Host)
		case *RP:
			compressionLenHelper(c, x.Mbox)
			compressionLenHelper(c, x.Txt)
		case *MINFO:
			compressionLenHelper(c, x.Rmail)
			compressionLenHelper(c, x.Email)
		case *AFSDB:
			compressionLenHelper(c, x.Hostname)
		case *SRV:
			compressionLenHelper(c, x.Target)
		case *NAPTR:
			compressionLenHelper(c, x.Replacement)
		case *RRSIG:
			compressionLenHelper(c, x.SignerName)
		case *NSEC:
			compressionLenHelper(c, x.NextDomain)
			// HIP?*/
	}
}

// Only search on compressing these types.
func compressionLenSearchType(c map[string]int, r RR) (int, bool) {
	switch x := r.(type) {
	case *NS:
		return compressionLenSearch(c, x.Ns)
	case *MX:
		return compressionLenSearch(c, x.Mx)
	case *CNAME:
		return compressionLenSearch(c, x.Target)
		/*case *DNAME:
			return compressionLenSearch(c, x.Target)
		case *PTR:
			return compressionLenSearch(c, x.Ptr)
		case *SOA:
			k, ok := compressionLenSearch(c, x.Ns)
			k1, ok1 := compressionLenSearch(c, x.Mbox)
			if !ok && !ok1 {
				return 0, false
			}
			return k + k1, true
		case *MB:
			return compressionLenSearch(c, x.Mb)
		case *MG:
			return compressionLenSearch(c, x.Mg)
		case *MR:
			return compressionLenSearch(c, x.Mr)
		case *MF:
			return compressionLenSearch(c, x.Mf)
		case *MD:
			return compressionLenSearch(c, x.Md)
		case *RT:
			return compressionLenSearch(c, x.Host)
		case *MINFO:
			k, ok := compressionLenSearch(c, x.Rmail)
			k1, ok1 := compressionLenSearch(c, x.Email)
			if !ok && !ok1 {
				return 0, false
			}
			return k + k1, true
		case *AFSDB:
			return compressionLenSearch(c, x.Hostname)*/
	}
	return 0, false
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}, www.miek.nl also returns []int{0, 4, 9}.
// The root name (.) returns nil. Also see SplitDomainName.
// s must be a syntactically valid domain name.
func Split(s string) []int {
	if s == "." {
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

// NextLabel returns the index of the start of the next label in the
// string s starting at offset.
// The bool end is true when the end of the string has been reached.
// Also see PrevLabel.
func NextLabel(s string, offset int) (i int, end bool) {
	quote := false
	for i = offset; i < len(s)-1; i++ {
		switch s[i] {
		case '\\':
			quote = !quote
		default:
			quote = false
		case '.':
			if quote {
				quote = !quote
				continue
			}
			return i + 1, false
		}
	}
	return i + 1, true
}
