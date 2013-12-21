package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"net"
	"fmt"
)

// TODO:gconnell switch endianness EVERYWHERE :(

// IEEE80211HT is the field type for the HT field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.6
type IEEE80211HT uint32
// IEEE80211QoS is the field type for the QoS field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.5
type IEEE80211QoS uint16
// IEEE80211QoS is the field type for the Duration/ID field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.2
type IEEE80211DurationID uint16

// IEEE80211 is the IEEE 802.11 MAC frame format.
// This implementation relied heavily on
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf
type IEEE80211 struct {
	BaseLayer
	Protocol byte  // should be zero for all current 802.11 specs.
	Type IEEE80211Type
	ToDS, FromDS, MoreFrag, Retry bool
	PowerManagement, MoreData, Protected, Order bool
	DurationID IEEE80211DurationID
	SequenceControlFragment byte
	SequenceControlNumber uint16
	QoS IEEE80211QoS
	HT IEEE80211HT
	Address1, Address2, Address3, Address4 net.HardwareAddr
	Checksum uint32
}

// Dst returns the destination MAC address for this frame.
func (i *IEEE80211) Dst() net.HardwareAddr {
	if i.ToDS {
		return i.Address3
	}
	return i.Address1
}
// Dst returns the source MAC address for this frame.
func (i *IEEE80211) Src() net.HardwareAddr {
	if i.ToDS {
		if i.FromDS {
			return i.Address4
		}
		return i.Address2
	}
	if i.FromDS {
		return i.Address3
	}
	return i.Address1
}
// Dst returns the receiver MAC address for this frame, if there is one.
func (i *IEEE80211) Receiver() net.HardwareAddr {
	if i.ToDS && i.FromDS {
		return i.Address1
	}
	return nil
}
// Dst returns the transmitter MAC address for this frame, if there is one.
func (i *IEEE80211) Transmitter() net.HardwareAddr {
	if i.ToDS && i.FromDS {
		return i.Address2
	}
	return nil
}
// Dst returns the BSSID MAC address for this frame, if there is one.
func (i *IEEE80211) BSSID() net.HardwareAddr {
	if i.ToDS {
		if i.FromDS {
			return nil
		}
		return i.Address1
	}
	if i.FromDS {
		return i.Address2
	}
	return i.Address3
}

// LayerType returns LayerTypeIEEE80211.
func (i *IEEE80211) LayerType() gopacket.LayerType { return LayerTypeIEEE80211 }

// LinkFlow returns the Src->Dst flow, with EndpointMAC.
func (i *IEEE80211) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, i.Src(), i.Dst())
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *IEEE80211) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 36 {
		return fmt.Errorf("802.11 packet size %d < 36", len(data))
	}
	i.Protocol = data[0] >> 6
	i.Type = IEEE80211Type(data[0] & 0x3f)
	i.ToDS = data[1] & 0x80 != 0
	i.FromDS = data[1] & 0x40 != 0
	i.MoreFrag = data[1] & 0x20 != 0
	i.Retry = data[1] & 0x10 != 0
	i.PowerManagement = data[1] & 0x08 != 0
	i.MoreData = data[1] & 0x04 != 0
	i.Protected = data[1] & 0x02 != 0
	i.Order = data[1] & 0x01 != 0
	i.DurationID = IEEE80211DurationID(binary.BigEndian.Uint16(data[2:4]))
	i.Address1 = net.HardwareAddr(data[4:10])
	i.Address2 = net.HardwareAddr(data[10:16])
	i.Address3 = net.HardwareAddr(data[16:22])
	i.SequenceControlFragment = data[22] >> 4
	i.SequenceControlNumber = binary.BigEndian.Uint16(data[22:24]) & 0x3f
	i.Address4 = net.HardwareAddr(data[24:30])
	i.QoS = IEEE80211QoS(binary.BigEndian.Uint16(data[30:32]))
	i.Checksum = binary.BigEndian.Uint32(data[len(data) - 4:])
	offset := 32
	if i.Order || i.Type == IEEE80211TypeControlWrapper {
		offset += 4
		i.HT = IEEE80211HT(binary.BigEndian.Uint32(data[32:36]))
	}
	i.BaseLayer = BaseLayer{data[:offset], data[offset:len(data) - 4]}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (i *IEEE80211) CanDecode() gopacket.LayerClass {
	return LayerTypeIEEE80211
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (i *IEEE80211) NextLayerType() gopacket.LayerType {
	fmt.Printf("    '%02x' next: %v\n", uint16(i.Type), i.Type.LayerType())
	return i.Type.LayerType()
}

func decodeIEEE80211(data []byte, p gopacket.PacketBuilder) error {
	i := &IEEE80211{}
	return decodingLayerDecoder(i, data, p)
}
