// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"errors"
	"fmt"
)

// EnumMetadata keeps track of a set of metadata for each enumeration value
// for protocol enumerations.
type EnumMetadata struct {
	// DecodeWith is the decoder to use to decode this protocol's data.
	DecodeWith gopacket.Decoder
	// Name is the name of the enumeration value.
	Name string
	// LayerType is the layer type implied by the given enum.
	LayerType gopacket.LayerType
}

// errorFunc returns a decoder that spits out a specific error message.
func errorFunc(msg string) gopacket.Decoder {
	var e = errors.New(msg)
	return gopacket.DecodeFunc(func([]byte, gopacket.PacketBuilder) error {
		return e
	})
}

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                EthernetType = 0
	EthernetTypeIPv4               EthernetType = 0x0800
	EthernetTypeARP                EthernetType = 0x0806
	EthernetTypeIPv6               EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery     EthernetType = 0x2000
	EthernetTypeNortelDiscovery    EthernetType = 0x01a2
	EthernetTypeDot1Q              EthernetType = 0x8100
	EthernetTypePPPoEDiscovery     EthernetType = 0x8863
	EthernetTypePPPoESession       EthernetType = 0x8864
	EthernetTypeMPLSUnicast        EthernetType = 0x8847
	EthernetTypeMPLSMulticast      EthernetType = 0x8848
	EthernetTypeEAPOL              EthernetType = 0x888e
	EthernetTypeLinkLayerDiscovery EthernetType = 0x88cc
	EthernetTypeEthernetCTP        EthernetType = 0x9000
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop IPProtocol = 0
	IPProtocolICMPv4       IPProtocol = 1
	IPProtocolIGMP         IPProtocol = 2
	IPProtocolTCP          IPProtocol = 6
	IPProtocolUDP          IPProtocol = 17
	IPProtocolRUDP         IPProtocol = 27
	IPProtocolIPv6         IPProtocol = 41
	IPProtocolIPv6Routing  IPProtocol = 43
	IPProtocolIPv6Fragment IPProtocol = 44
	IPProtocolGRE          IPProtocol = 47
	IPProtocolESP          IPProtocol = 50
	IPProtocolAH           IPProtocol = 51
	IPProtocolICMPv6       IPProtocol = 58
	IPProtocolNoNextHeader IPProtocol = 59
	IPProtocolIPIP         IPProtocol = 94
	IPProtocolEtherIP      IPProtocol = 97
	IPProtocolSCTP         IPProtocol = 132
	IPProtocolUDPLite      IPProtocol = 136
	IPProtocolMPLSInIP     IPProtocol = 137
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType uint8

const (
	// According to pcap-linktype(7).
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
)

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode uint8

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4          PPPType = 0x0021
	PPPTypeIPv6          PPPType = 0x0057
	PPPTypeMPLSUnicast   PPPType = 0x0281
	PPPTypeMPLSMulticast PPPType = 0x0283
)

// SCTPChunkType is an enumeration of chunk types inside SCTP packets.
type SCTPChunkType uint8

const (
	SCTPChunkTypeData             SCTPChunkType = 0
	SCTPChunkTypeInit             SCTPChunkType = 1
	SCTPChunkTypeInitAck          SCTPChunkType = 2
	SCTPChunkTypeSack             SCTPChunkType = 3
	SCTPChunkTypeHeartbeat        SCTPChunkType = 4
	SCTPChunkTypeHeartbeatAck     SCTPChunkType = 5
	SCTPChunkTypeAbort            SCTPChunkType = 6
	SCTPChunkTypeShutdown         SCTPChunkType = 7
	SCTPChunkTypeShutdownAck      SCTPChunkType = 8
	SCTPChunkTypeError            SCTPChunkType = 9
	SCTPChunkTypeCookieEcho       SCTPChunkType = 10
	SCTPChunkTypeCookieAck        SCTPChunkType = 11
	SCTPChunkTypeShutdownComplete SCTPChunkType = 14
)

// FDDIFrameControl is an enumeration of FDDI frame control bytes.
type FDDIFrameControl uint8

const (
	FDDIFrameControlLLC FDDIFrameControl = 0x50
)

// EAPOLType is an enumeration of EAPOL packet types.
type EAPOLType uint8

const (
	EAPOLTypeEAP      EAPOLType = 0
	EAPOLTypeStart    EAPOLType = 1
	EAPOLTypeLogOff   EAPOLType = 2
	EAPOLTypeKey      EAPOLType = 3
	EAPOLTypeASFAlert EAPOLType = 4
)

// ProtocolFamily is the set of values defined as PF_* in sys/socket.h
type ProtocolFamily uint8

type IEEE80211Type uint8

const ieee80211MainTypeMask = 0x3

// mainType returns the main type of an IEEE 802.11 type.
func (i IEEE80211Type) mainType() IEEE80211Type {
	return i & ieee80211MainTypeMask
}

// hasQoS returns true if the type has a QoS field.
func (i IEEE80211Type) hasQoS() bool {
	return i.mainType() == ieee80211MainTypeData && i&0x20 != 0
}

const (
	ieee80211MainTypeManagement = 0x00
	ieee80211MainTypeControl    = 0x01
	ieee80211MainTypeData       = 0x02
	// Management
	IEEE80211TypeAssociationRequest    IEEE80211Type = 0x00
	IEEE80211TypeAssociationResponse   IEEE80211Type = 0x04
	IEEE80211TypeReassociationRequest  IEEE80211Type = 0x08
	IEEE80211TypeReassociationResponse IEEE80211Type = 0x0c
	IEEE80211TypeProbeRequest          IEEE80211Type = 0x10
	IEEE80211TypeProbeResponse         IEEE80211Type = 0x14
	IEEE80211TypeTimingAdvertisement   IEEE80211Type = 0x18
	IEEE80211TypeBeacon                IEEE80211Type = 0x20
	IEEE80211TypeATIM                  IEEE80211Type = 0x24
	IEEE80211TypeDisassociation        IEEE80211Type = 0x28
	IEEE80211TypeAuthentication        IEEE80211Type = 0x2c
	IEEE80211TypeDeauthentication      IEEE80211Type = 0x30
	IEEE80211TypeAction                IEEE80211Type = 0x34
	IEEE80211TypeActionNoAck           IEEE80211Type = 0x38
	// Control
	IEEE80211TypeControlWrapper IEEE80211Type = 0x1d
	IEEE80211TypeBlockAckReq    IEEE80211Type = 0x21
	IEEE80211TypeBlockAck       IEEE80211Type = 0x25
	IEEE80211TypePSPoll         IEEE80211Type = 0x29
	IEEE80211TypeRTS            IEEE80211Type = 0x2d
	IEEE80211TypeCTS            IEEE80211Type = 0x31
	IEEE80211TypeACK            IEEE80211Type = 0x35
	IEEE80211TypeCFEnd          IEEE80211Type = 0x39
	IEEE80211TypeCFEndCFAck     IEEE80211Type = 0x3d
	// Data
	IEEE80211TypeData               IEEE80211Type = 0x02
	IEEE80211TypeDataCFAck          IEEE80211Type = 0x06
	IEEE80211TypeDataCFPoll         IEEE80211Type = 0x0a
	IEEE80211TypeDataCFAckCFPoll    IEEE80211Type = 0x0e
	IEEE80211TypeNull               IEEE80211Type = 0x12
	IEEE80211TypeCFAck              IEEE80211Type = 0x16
	IEEE80211TypeCFPoll             IEEE80211Type = 0x1a
	IEEE80211TypeCFAckCFPoll        IEEE80211Type = 0x1e
	IEEE80211TypeQoSData            IEEE80211Type = 0x22
	IEEE80211TypeQoSDataCFAck       IEEE80211Type = 0x26
	IEEE80211TypeQoSDataCFPoll      IEEE80211Type = 0x2a
	IEEE80211TypeQoSDataCFAckCFPoll IEEE80211Type = 0x2e
	IEEE80211TypeQoSNull            IEEE80211Type = 0x32
	IEEE80211TypeQoSCFPoll          IEEE80211Type = 0x3a
	IEEE80211TypeQoSCFAckCFPoll     IEEE80211Type = 0x3e
)

var (
	// Each of the following arrays contains mappings of how to handle enum
	// values for various enum types in gopacket/layers.
	//
	// So, EthernetTypeMetadata[2] contains information on how to handle EthernetType
	// 2, including which name to give it and which decoder to use to decode
	// packet data of that type.  These arrays are filled by default with all of the
	// protocols gopacket/layers knows how to handle, but users of the library can
	// add new decoders or override existing ones.  For example, if you write a better
	// TCP decoder, you can override IPProtocolMetadata[IPProtocolTCP].DecodeWith
	// with your new decoder, and all gopacket/layers decoding will use your new
	// decoder whenever they encounter that IPProtocol.
	EthernetTypeMetadata     [65536]EnumMetadata
	IPProtocolMetadata       [265]EnumMetadata
	SCTPChunkTypeMetadata    [265]EnumMetadata
	PPPTypeMetadata          [65536]EnumMetadata
	PPPoECodeMetadata        [256]EnumMetadata
	LinkTypeMetadata         [256]EnumMetadata
	FDDIFrameControlMetadata [256]EnumMetadata
	EAPOLTypeMetadata        [256]EnumMetadata
	ProtocolFamilyMetadata   [256]EnumMetadata
	IEEE80211TypeMetadata    [256]EnumMetadata
)

func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EthernetTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a EthernetType) String() string {
	return EthernetTypeMetadata[a].Name
}
func (a EthernetType) LayerType() gopacket.LayerType {
	return EthernetTypeMetadata[a].LayerType
}
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
}
func (a IPProtocol) String() string {
	return IPProtocolMetadata[a].Name
}
func (a IPProtocol) LayerType() gopacket.LayerType {
	return IPProtocolMetadata[a].LayerType
}
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return SCTPChunkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a SCTPChunkType) String() string {
	return SCTPChunkTypeMetadata[a].Name
}
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPType) String() string {
	return PPPTypeMetadata[a].Name
}
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return LinkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a LinkType) String() string {
	return LinkTypeMetadata[a].Name
}
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPoECodeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPoECode) String() string {
	return PPPoECodeMetadata[a].Name
}
func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	return FDDIFrameControlMetadata[a].DecodeWith.Decode(data, p)
}
func (a FDDIFrameControl) String() string {
	return FDDIFrameControlMetadata[a].Name
}
func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EAPOLTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a EAPOLType) String() string {
	return EAPOLTypeMetadata[a].Name
}
func (a EAPOLType) LayerType() gopacket.LayerType {
	return EAPOLTypeMetadata[a].LayerType
}
func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	return ProtocolFamilyMetadata[a].DecodeWith.Decode(data, p)
}
func (a ProtocolFamily) String() string {
	return ProtocolFamilyMetadata[a].Name
}
func (a IEEE80211Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	return IEEE80211TypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a IEEE80211Type) String() string {
	return IEEE80211TypeMetadata[a].Name
}
func (a IEEE80211Type) LayerType() gopacket.LayerType {
	return IEEE80211TypeMetadata[a].LayerType
}

// Decode a raw v4 or v6 IP packet.
func decodeIPv4or6(data []byte, p gopacket.PacketBuilder) error {
	version := data[0] >> 4
	switch version {
	case 4:
		return decodeIPv4(data, p)
	case 6:
		return decodeIPv6(data, p)
	}
	return fmt.Errorf("Invalid IP packet version %v", version)
}

func init() {
	// Here we link up all enumerations with their respective names and decoders.
	for i := 0; i < 65536; i++ {
		EthernetTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode ethernet type %d", i)),
			Name:       fmt.Sprintf("UnknownEthernetType(%d)", i),
		}
		PPPTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode PPP type %d", i)),
			Name:       fmt.Sprintf("UnknownPPPType(%d)", i),
		}
	}
	for i := 0; i < 256; i++ {
		IPProtocolMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode IP protocol %d", i)),
			Name:       fmt.Sprintf("UnknownIPProtocol(%d)", i),
		}
		SCTPChunkTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode SCTP chunk type %d", i)),
			Name:       fmt.Sprintf("UnknownSCTPChunkType(%d)", i),
		}
		PPPoECodeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode PPPoE code %d", i)),
			Name:       fmt.Sprintf("UnknownPPPoECode(%d)", i),
		}
		LinkTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode link type %d", i)),
			Name:       fmt.Sprintf("UnknownLinkType(%d)", i),
		}
		FDDIFrameControlMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode FDDI frame control %d", i)),
			Name:       fmt.Sprintf("UnknownFDDIFrameControl(%d)", i),
		}
		EAPOLTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode EAPOL type %d", i)),
			Name:       fmt.Sprintf("UnknownEAPOLType(%d)", i),
		}
		ProtocolFamilyMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode protocol family %d", i)),
			Name:       fmt.Sprintf("UnknownProtocolFamily(%d)", i),
		}
		IEEE80211TypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode IEEE 802.11 type %d", i)),
			Name:       fmt.Sprintf("UnknownIEEE80211Type(%d)", i),
		}
	}

	EthernetTypeMetadata[EthernetTypeLLC] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLLC), Name: "LLC", LayerType: LayerTypeLLC}
	EthernetTypeMetadata[EthernetTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	EthernetTypeMetadata[EthernetTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	EthernetTypeMetadata[EthernetTypeARP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeARP), Name: "ARP", LayerType: LayerTypeARP}
	EthernetTypeMetadata[EthernetTypeDot1Q] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot1Q), Name: "Dot1Q", LayerType: LayerTypeDot1Q}
	EthernetTypeMetadata[EthernetTypePPPoEDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoEDiscovery", LayerType: LayerTypePPPoE}
	EthernetTypeMetadata[EthernetTypePPPoESession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoESession", LayerType: LayerTypePPPoE}
	EthernetTypeMetadata[EthernetTypeEthernetCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernetCTP), Name: "EthernetCTP", LayerType: LayerTypeEthernetCTP}
	EthernetTypeMetadata[EthernetTypeCiscoDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeCiscoDiscovery), Name: "CiscoDiscovery", LayerType: LayerTypeCiscoDiscovery}
	EthernetTypeMetadata[EthernetTypeNortelDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeNortelDiscovery), Name: "NortelDiscovery", LayerType: LayerTypeNortelDiscovery}
	EthernetTypeMetadata[EthernetTypeLinkLayerDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLinkLayerDiscovery), Name: "LinkLayerDiscovery", LayerType: LayerTypeLinkLayerDiscovery}
	EthernetTypeMetadata[EthernetTypeMPLSUnicast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSUnicast", LayerType: LayerTypeMPLS}
	EthernetTypeMetadata[EthernetTypeMPLSMulticast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSMulticast", LayerType: LayerTypeMPLS}
	EthernetTypeMetadata[EthernetTypeEAPOL] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEAPOL), Name: "EAPOL", LayerType: LayerTypeEAPOL}

	IPProtocolMetadata[IPProtocolTCP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeTCP), Name: "TCP", LayerType: LayerTypeTCP}
	IPProtocolMetadata[IPProtocolUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDP), Name: "UDP", LayerType: LayerTypeUDP}
	IPProtocolMetadata[IPProtocolICMPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeICMPv4), Name: "ICMPv4", LayerType: LayerTypeICMPv4}
	IPProtocolMetadata[IPProtocolICMPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeICMPv6), Name: "ICMPv6", LayerType: LayerTypeICMPv6}
	IPProtocolMetadata[IPProtocolSCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTP), Name: "SCTP", LayerType: LayerTypeSCTP}
	IPProtocolMetadata[IPProtocolIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	IPProtocolMetadata[IPProtocolIPIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	IPProtocolMetadata[IPProtocolEtherIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEtherIP), Name: "EtherIP", LayerType: LayerTypeEtherIP}
	IPProtocolMetadata[IPProtocolRUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeRUDP), Name: "RUDP", LayerType: LayerTypeRUDP}
	IPProtocolMetadata[IPProtocolGRE] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeGRE), Name: "GRE", LayerType: LayerTypeGRE}
	IPProtocolMetadata[IPProtocolIPv6HopByHop] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6HopByHop), Name: "IPv6HopByHop", LayerType: LayerTypeIPv6HopByHop}
	IPProtocolMetadata[IPProtocolIPv6Routing] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Routing), Name: "IPv6Routing", LayerType: LayerTypeIPv6Routing}
	IPProtocolMetadata[IPProtocolIPv6Fragment] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Fragment), Name: "IPv6Fragment", LayerType: LayerTypeIPv6Fragment}
	IPProtocolMetadata[IPProtocolAH] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecAH), Name: "IPSecAH", LayerType: LayerTypeIPSecAH}
	IPProtocolMetadata[IPProtocolESP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecESP), Name: "IPSecESP", LayerType: LayerTypeIPSecESP}
	IPProtocolMetadata[IPProtocolUDPLite] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDPLite), Name: "UDPLite", LayerType: LayerTypeUDPLite}
	IPProtocolMetadata[IPProtocolMPLSInIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLS", LayerType: LayerTypeMPLS}
	IPProtocolMetadata[IPProtocolNoNextHeader] = EnumMetadata{DecodeWith: errorFunc("NoNextHeader with non-zero byte payload"), Name: "NoNextHeader"}
	IPProtocolMetadata[IPProtocolIGMP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIGMP), Name: "IGMP", LayerType: LayerTypeIGMP}

	SCTPChunkTypeMetadata[SCTPChunkTypeData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPData), Name: "Data"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInit] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "Init"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInitAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "InitAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeSack] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPSack), Name: "Sack"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeat] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "Heartbeat"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeatAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "HeartbeatAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeAbort] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Abort"}
	SCTPChunkTypeMetadata[SCTPChunkTypeError] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Error"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdown] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdown), Name: "Shutdown"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdownAck), Name: "ShutdownAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieEcho] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPCookieEcho), Name: "CookieEcho"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "CookieAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownComplete] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "ShutdownComplete"}

	PPPTypeMetadata[PPPTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	PPPTypeMetadata[PPPTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	PPPTypeMetadata[PPPTypeMPLSUnicast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSUnicast"}
	PPPTypeMetadata[PPPTypeMPLSMulticast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSMulticast"}

	PPPoECodeMetadata[PPPoECodeSession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}

	LinkTypeMetadata[LinkTypeEthernet] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernet), Name: "Ethernet"}
	LinkTypeMetadata[LinkTypePPP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}
	LinkTypeMetadata[LinkTypeFDDI] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeFDDI), Name: "FDDI"}
	LinkTypeMetadata[LinkTypeNull] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLoopback), Name: "Null"}
	LinkTypeMetadata[LinkTypeLoop] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLoopback), Name: "Loop"}
	LinkTypeMetadata[LinkTypeRaw] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4or6), Name: "Raw"}
	LinkTypeMetadata[LinkTypeIEEE802_11] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIEEE80211), Name: "IEEE80211"}

	FDDIFrameControlMetadata[FDDIFrameControlLLC] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLLC), Name: "LLC"}

	EAPOLTypeMetadata[EAPOLTypeEAP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEAP), Name: "EAP", LayerType: LayerTypeEAP}

	ProtocolFamilyMetadata[ProtocolFamilyIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6BSD] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6FreeBSD] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6Darwin] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6Linux] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}

	IEEE80211TypeMetadata[IEEE80211TypeAssociationRequest] = EnumMetadata{Name: "AssociationRequest"}
	IEEE80211TypeMetadata[IEEE80211TypeAssociationResponse] = EnumMetadata{Name: "AssociationResponse"}
	IEEE80211TypeMetadata[IEEE80211TypeReassociationRequest] = EnumMetadata{Name: "ReassociationRequest"}
	IEEE80211TypeMetadata[IEEE80211TypeReassociationResponse] = EnumMetadata{Name: "ReassociationResponse"}
	IEEE80211TypeMetadata[IEEE80211TypeProbeRequest] = EnumMetadata{Name: "ProbeRequest"}
	IEEE80211TypeMetadata[IEEE80211TypeProbeResponse] = EnumMetadata{Name: "ProbeResponse"}
	IEEE80211TypeMetadata[IEEE80211TypeTimingAdvertisement] = EnumMetadata{Name: "TimingAdvertisement"}
	IEEE80211TypeMetadata[IEEE80211TypeBeacon] = EnumMetadata{Name: "Beacon"}
	IEEE80211TypeMetadata[IEEE80211TypeATIM] = EnumMetadata{Name: "ATIM"}
	IEEE80211TypeMetadata[IEEE80211TypeDisassociation] = EnumMetadata{Name: "Disassociation"}
	IEEE80211TypeMetadata[IEEE80211TypeAuthentication] = EnumMetadata{Name: "Authentication"}
	IEEE80211TypeMetadata[IEEE80211TypeDeauthentication] = EnumMetadata{Name: "Deauthentication"}
	IEEE80211TypeMetadata[IEEE80211TypeAction] = EnumMetadata{Name: "Action"}
	IEEE80211TypeMetadata[IEEE80211TypeActionNoAck] = EnumMetadata{Name: "ActionNoAck"}
	IEEE80211TypeMetadata[IEEE80211TypeControlWrapper] = EnumMetadata{Name: "ControlWrapper"}
	IEEE80211TypeMetadata[IEEE80211TypeBlockAckReq] = EnumMetadata{Name: "BlockAckReq"}
	IEEE80211TypeMetadata[IEEE80211TypeBlockAck] = EnumMetadata{Name: "BlockAck"}
	IEEE80211TypeMetadata[IEEE80211TypePSPoll] = EnumMetadata{Name: "PSPoll"}
	IEEE80211TypeMetadata[IEEE80211TypeRTS] = EnumMetadata{Name: "RTS"}
	IEEE80211TypeMetadata[IEEE80211TypeCTS] = EnumMetadata{Name: "CTS"}
	IEEE80211TypeMetadata[IEEE80211TypeACK] = EnumMetadata{Name: "ACK"}
	IEEE80211TypeMetadata[IEEE80211TypeCFEnd] = EnumMetadata{Name: "CFEnd"}
	IEEE80211TypeMetadata[IEEE80211TypeCFEndCFAck] = EnumMetadata{Name: "CFEndCFAck"}
	IEEE80211TypeMetadata[IEEE80211TypeData] = EnumMetadata{Name: "Data", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeDataCFAck] = EnumMetadata{Name: "DataCFAck", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeDataCFPoll] = EnumMetadata{Name: "DataCFPoll", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeDataCFAckCFPoll] = EnumMetadata{Name: "DataCFAckCFPoll", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeNull] = EnumMetadata{Name: "Null"}
	IEEE80211TypeMetadata[IEEE80211TypeCFAck] = EnumMetadata{Name: "CFAck"}
	IEEE80211TypeMetadata[IEEE80211TypeCFPoll] = EnumMetadata{Name: "CFPoll"}
	IEEE80211TypeMetadata[IEEE80211TypeCFAckCFPoll] = EnumMetadata{Name: "CFAckCFPoll"}
	IEEE80211TypeMetadata[IEEE80211TypeQoSData] = EnumMetadata{Name: "QoSData", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeQoSDataCFAck] = EnumMetadata{Name: "QoSDataCFAck", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeQoSDataCFPoll] = EnumMetadata{Name: "QoSDataCFPoll", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeQoSDataCFAckCFPoll] = EnumMetadata{Name: "QoSDataCFAckCFPoll", DecodeWith: gopacket.DecodeFunc(decodeLLC), LayerType: LayerTypeLLC}
	IEEE80211TypeMetadata[IEEE80211TypeQoSNull] = EnumMetadata{Name: "QoSNull"}
	IEEE80211TypeMetadata[IEEE80211TypeQoSCFPoll] = EnumMetadata{Name: "QoSCFPoll"}
	IEEE80211TypeMetadata[IEEE80211TypeQoSCFAckCFPoll] = EnumMetadata{Name: "QoSCFAckCFPoll"}
}
