/*dns报文格式：
+---------------------+
    |        Header       | 报文头
    +---------------------+
    |       Question      | 查询的问题
    +---------------------+
    |        Answer       | 应答
    +---------------------+
    |      Authority      | 授权应答
    +---------------------+
    |      Additional     | 附加信息
    +---------------------+
报文头部
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
question格式：
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
package models

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeMD    = 3
	dnsTypeMF    = 4
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypeMB    = 7
	dnsTypeMG    = 8
	dnsTypeMR    = 9
	dnsTypeNULL  = 10
	dnsTypeWKS   = 11
	dnsTypePTR   = 12
	dnsTypeHINFO = 13
	dnsTypeMINFO = 14
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33

	dnsTypeAXFR  = 252
	dnsTypeMAILB = 253
	dnsTypeMAILA = 254
	dnsTypeALL   = 255

	dnsClassINET   = 1
	dnsClassCSNET  = 2
	dnsClassCHAOS  = 3
	dnsClassHESIOD = 4
	dnsClassANY    = 255

	dnsRcodeSuccess        = 0
	dnsRcodeFormatError    = 1
	dnsRcodeServerFailure  = 2
	dnsRcodeNameError      = 3
	dnsRcodeNotImplemented = 4
	dnsRcodeRefused        = 5
)

type DNSHeader struct {
	ID         uint16
	FlagHeader uint16
	QDCOUNT    uint16
	ANCOUNT    uint16
	NSCOUNT    uint16
	ARCOUNT    uint16
}

func (header *DNSHeader) SetFlag(QR uint16, OperationCode uint16, AuthoritativeAnswer uint16, Truncation uint16, RecursionDesired uint16, RecursionAvailable uint16, ResponseCode uint16) {
	header.FlagHeader = QR<<15 + OperationCode<<11 + AuthoritativeAnswer<<10 + Truncation<<9 + RecursionDesired<<8 + RecursionAvailable<<7 + ResponseCode
}

type DNSQuery struct {
	QuestionType  uint16
	QuestionClass uint16
}

type dnsAnswer struct {
	Name   uint16
	Qtype  uint16
	Qclass uint16
	QLive  uint32
	QLen   uint16
	CName  string
}

func ParseDomainName(domain string) []byte {

	var (
		buffer   bytes.Buffer
		segments []string = strings.Split(domain, ".")
	)
	for _, seg := range segments {
		binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
		binary.Write(&buffer, binary.BigEndian, []byte(seg))
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))

	return buffer.Bytes()
}

func send(ns_server string, domain string, qtype uint16, time_set time.Duration) (dns Msg, err error) {
	var (
		dns_header   DNSHeader
		dns_question DNSQuery
	)

	dns_header.ID = 0xFFFF
	dns_header.SetFlag(0, 0, 0, 0, 1, 0, 0)
	dns_header.QDCOUNT = 1
	dns_header.ANCOUNT = 0
	dns_header.NSCOUNT = 0
	dns_header.ARCOUNT = 0

	dns_question.QuestionType = qtype
	dns_question.QuestionClass = 1

	var (
		conn net.Conn

		buffer bytes.Buffer
	)

	conn, err = net.DialTimeout("udp", ns_server+":53", time_set)

	if err != nil {

		return
	}

	defer conn.Close()

	binary.Write(&buffer, binary.BigEndian, dns_header)
	binary.Write(&buffer, binary.BigEndian, ParseDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, dns_question)

	if _, err = conn.Write(buffer.Bytes()); err != nil {

		return
	}
LOOP:
	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	if _, err = conn.Read(msg); err != nil {

		return
	}

	if len(msg) == 0 {
		fmt.Println("no datas return")
		return
	}

	dns.Unpack(msg)
	if len(dns.Ns) == 0 {
		goto LOOP
	}
	return
}
