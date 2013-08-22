package afpacket

// Couldn't have done this without:
// http://lxr.free-electrons.com/source/Documentation/networking/packet_mmap.txt
// http://codemonkeytips.blogspot.co.uk/2011/07/asynchronous-packet-socket-reading-with.html

import (
	"code.google.com/p/gopacket"
	"net"
	"log"
	"os"
	"reflect"
	"unsafe"
	"errors"
	"time"
	"sync"
)

/*
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <linux/if_ether.h>  // ETH_P_ALL
#include <sys/socket.h>  // socket()
#include <errno.h>  // errno
#include <string.h>  // strerror()
#include <unistd.h>  // close()
#include <arpa/inet.h>  // htons()
#include <sys/mman.h>  // mmap(), munmap()
#include <poll.h>  // poll()

int getSockaddrOffset() {
	return TPACKET_ALIGN(sizeof(struct tpacket_hdr));
}
int getPacketOffset() {
	return getSockaddrOffset() +
	       TPACKET_ALIGN(sizeof(struct sockaddr_ll));
}
*/
import "C"

var sockaddrOffset = uintptr(C.getSockaddrOffset())
var packetOffset = uintptr(C.getPacketOffset())

type Stats struct {
	Packets int64
	Polls int64
}

type Handle struct {
	f *os.File
	ring unsafe.Pointer
	offset int
	framesize, frames int
	mu sync.Mutex  // guards below
	pollset C.struct_pollfd
	shouldReleasePacket bool
	Stats Stats
}

func (h *Handle) bind(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	log.Println("binding", ifaceName, iface.Index)
	var ll C.struct_sockaddr_ll
	ll.sll_family = C.AF_PACKET
	ll.sll_protocol = C.__be16(C.htons(C.ETH_P_ALL))
	ll.sll_ifindex = C.int(iface.Index)
	if _, err := C.bind(C.int(h.f.Fd()), (*C.struct_sockaddr)(unsafe.Pointer(&ll)), C.socklen_t(unsafe.Sizeof(ll))); err != nil {
		return err
	}
	log.Println("bind success")
	return nil
}

func (h *Handle) setUpRing() (err error) {
	var tp C.struct_tpacket_req
	tp.tp_block_size = C.uint(h.frames) * C.uint(h.framesize)
	tp.tp_block_nr = 1
	tp.tp_frame_size = C.uint(h.framesize)
	tp.tp_frame_nr = C.uint(h.frames)
	log.Println("setting up ring")
	if _, err := C.setsockopt(C.int(h.f.Fd()), C.SOL_PACKET, C.PACKET_RX_RING, unsafe.Pointer(&tp), C.socklen_t(unsafe.Sizeof(tp))); err != nil {
		return err
	}
	log.Println("mmapping")
	if h.ring, err = C.mmap(nil, C.size_t(tp.tp_block_size * tp.tp_block_nr), C.PROT_READ | C.PROT_WRITE, C.MAP_SHARED, C.int(h.f.Fd()), 0); err != nil {
		return
	}
	if h.ring == nil {
		return errors.New("no ring")
	}
	return nil
}

func (h *Handle) Close() {
	log.Println("closing")
	h.f.Close()
}

type OptSnaplen int
type OptFrames int

func NewHandle(ifaceName string, opts... interface{}) (*Handle, error) {
	fd, err := C.socket(C.AF_PACKET, C.SOCK_RAW, C.int(C.htons(C.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	psize := int(C.getpagesize())
	h := &Handle{
		f: os.NewFile(uintptr(fd), ifaceName),
		frames: 1024,
		framesize: psize * 4,
	}
	for _, opt := range opts {
		switch v := opt.(type) {
		case OptSnaplen:
			h.framesize = (int(v) / psize + 1) * psize
		case OptFrames:
			h.frames = int(v)
		}
	}
	log.Printf("Frame size %d %x\n", h.framesize, h.framesize)
	log.Println("packet offset", packetOffset)
	if err = h.bind(ifaceName); err == nil {
		if err = h.setUpRing(); err == nil {
			return h, nil
		}
	}
	h.Close()
	return nil, err
}

func (h *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if h.ring == nil {
		log.Println("Not using ring")
		ci.CaptureLength, err = h.f.Read(data)
		ci.Timestamp = time.Now()
		return
	}
	// We're reading from the ring... scary!
	h.mu.Lock()
	defer h.mu.Unlock()

	h.releaseOldPacket()
	hdr := h.getTPacketHeader()
	if err = h.pollForFirstPacket(hdr); err != nil {
		return
	}
	switch {
	case hdr.tp_status & C.TP_STATUS_COPY != 0:
		err = errors.New("incomplete packet")
	case hdr.tp_status & C.TP_STATUS_LOSING != 0:
		fallthrough
	default:
		if hdr.tp_len == 0 {
			err = errors.New("zero-length packet")
			return
		}
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		slice.Data = uintptr(unsafe.Pointer(hdr)) + uintptr(hdr.tp_mac)
		slice.Len = int(hdr.tp_len)
		slice.Cap = h.framesize - int(hdr.tp_mac)
		ci.Timestamp = time.Unix(int64(hdr.tp_sec), int64(hdr.tp_usec) * 1000)
		ci.CaptureLength = slice.Len
		ci.Length = int(hdr.tp_len)
		h.Stats.Packets++
	}
	return
}

func packetData(packet *C.struct_tpacket_hdr) uintptr {
  return uintptr(unsafe.Pointer(packet)) + packetOffset
}

func (h *Handle) getTPacketHeader() *C.struct_tpacket_hdr {
	position := uintptr(h.ring) + uintptr(h.framesize * h.offset)
	return (*C.struct_tpacket_hdr)(unsafe.Pointer(position))
}

func (h *Handle) getSockaddrHeader() *C.struct_sockaddr_ll {
	position := uintptr(h.ring) + uintptr(h.framesize * h.offset) + sockaddrOffset
	return (*C.struct_sockaddr_ll)(unsafe.Pointer(position))
}

func (h *Handle) pollForFirstPacket(hdr *C.struct_tpacket_hdr) error {
	for hdr.tp_status & C.TP_STATUS_USER == 0 {
		h.pollset.fd = C.int(h.f.Fd())
		h.pollset.events = C.POLLIN
		h.pollset.revents = 0
		_, err := C.poll(&h.pollset, 1, -1);
		h.Stats.Polls++
		if err != nil {
			return err
		}
	}
	h.shouldReleasePacket = true
	return nil
}

var count int

func (h *Handle) releaseOldPacket() {
	if !h.shouldReleasePacket {
		return
	}
	h.shouldReleasePacket = false
	hdr := h.getTPacketHeader()
	hdr.tp_status = 0
	h.offset = (h.offset + 1) % h.frames
	count++
}
