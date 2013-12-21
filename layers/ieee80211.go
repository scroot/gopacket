// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
	"net"
)

// TODO:gconnell switch endianness EVERYWHERE :(

// IEEE80211HT is the field type for the HT field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.6
type IEEE80211HT uint32

// IEEE80211QoS is the field type for the QoS field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.5
type IEEE80211QoS uint16

// amsduPresent returns whether A-MSDU is present in the packet.  Only applicable
// to certain packet types.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf table 8-4
func (i IEEE80211QoS) amsduPresent() bool {
	return i&0x8000 != 0
}

// IEEE80211QoS is the field type for the Duration/ID field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.2
type IEEE80211DurationID uint16

// IEEE80211SequenceControl is the field type for the Sequence control field of IEEE 802.11.  See
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf section 8.2.4.4
type IEEE80211SequenceControl uint16

// IEEE80211 is the IEEE 802.11 MAC frame format.
// This implementation relied heavily on
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf
// Currently we only implement Data packets.
type IEEE80211 struct {
	// Note that the Contents field for IEEE80211 packets doesn't
	// return data that's entirely correct.  The Checksum field is
	// stored at the end of the packet, after its encapsulated data.
	// We only store the data before the encapsulated data in the
	// BaseLayer.Contents field, since we only have a single slice
	// to work with.
	BaseLayer
	Protocol                                    byte // should be zero for all current 802.11 specs.
	Type                                        IEEE80211Type
	ToDS, FromDS, MoreFrag, Retry               bool
	PowerManagement, MoreData, Protected, Order bool
	DurationID                                  IEEE80211DurationID
	SequenceControl                             IEEE80211SequenceControl

	// These optional fields are set to nil if they don't appear in the frame.
	QoS *IEEE80211QoS
	qos IEEE80211QoS
	HT  *IEEE80211HT
	ht  IEEE80211HT

	BSSID, DA, SA, RA, TA net.HardwareAddr
	Checksum              uint32
}

// LayerType returns LayerTypeIEEE80211.
func (i *IEEE80211) LayerType() gopacket.LayerType { return LayerTypeIEEE80211 }

// LinkFlow returns the Src->Dst flow, with EndpointMAC.
func (i *IEEE80211) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, i.TA, i.RA)
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *IEEE80211) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	original := data
	if len(data) < 36 {
		return fmt.Errorf("802.11 packet size %d < 36", len(data))
	}
	// clean out any fields we need to:
	*i = IEEE80211{}

	// Start actual decoding.
	i.Protocol = data[0] & 0x3
	i.Type = IEEE80211Type(data[0] >> 2)
	if i.Type.mainType() != ieee80211MainTypeData {
		return fmt.Errorf("can only decode data packets for IEEE 802.11")
	}
	i.ToDS = data[1]&0x01 != 0
	i.FromDS = data[1]&0x02 != 0
	i.MoreFrag = data[1]&0x04 != 0
	i.Retry = data[1]&0x08 != 0
	i.PowerManagement = data[1]&0x10 != 0
	i.MoreData = data[1]&0x20 != 0
	i.Protected = data[1]&0x40 != 0
	i.Order = data[1]&0x80 != 0
	i.DurationID = IEEE80211DurationID(binary.BigEndian.Uint16(data[2:4]))
	i.Checksum = binary.BigEndian.Uint32(data[len(data)-4:])

	// Strip off everything we've done so far.  From here on, we'll continue to
	// modify the data slice as we pull off bits of the frame.
	data = data[4 : len(data)-4]
	offset := 4

	// Data type defined in section 8.3.2.1
	addr1, addr2, addr3 := net.HardwareAddr(data[:6]), net.HardwareAddr(data[6:12]), net.HardwareAddr(data[12:18])
	i.SequenceControl = IEEE80211SequenceControl(binary.BigEndian.Uint16(data[18:20]))

	i.RA = addr1
	i.TA = addr2
	data = data[20:]
	offset += 20
	switch {
	case !i.ToDS && !i.FromDS:
		i.DA = addr1
		i.SA = addr2
		i.BSSID = addr3
	case !i.ToDS && i.FromDS:
		i.DA = addr1
		i.BSSID = addr2
	case i.ToDS && !i.FromDS:
		i.BSSID = addr1
		i.SA = addr2
		i.DA = addr3
	case i.ToDS && i.FromDS:
		i.DA = addr3
		i.SA = net.HardwareAddr(data[:6])
		offset += 6
	}
	if i.Type.hasQoS() {
		i.QoS = &i.qos
		i.qos = IEEE80211QoS(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		offset += 2
		if i.Order {
			i.HT = &i.ht
			i.ht = IEEE80211HT(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			offset += 2
		}
	}
	i.BaseLayer = BaseLayer{Payload: data, Contents: original[:offset]}
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
