package afpacket

// Couldn't have done this without:
// http://lxr.free-electrons.com/source/Documentation/networking/packet_mmap.txt
// http://codemonkeytips.blogspot.co.uk/2011/07/asynchronous-packet-socket-reading-with.html

import (
	"code.google.com/p/gopacket"
	"net"
	"log"
	"os"
	"unsafe"
	"errors"
	"time"
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
*/
import "C"

type Handle struct {
	f *os.File
	ring unsafe.Pointer
	offset int
	framesize, frames int
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
	if ret, err := C.bind(C.int(h.f.Fd()), (*C.struct_sockaddr)(unsafe.Pointer(&ll)), C.socklen_t(unsafe.Sizeof(ll))); err != nil {
		return err
	} else if ret < 0 {
		return errors.New("bind fail")
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
	if ret, err := C.setsockopt(C.int(h.f.Fd()), C.SOL_PACKET, C.PACKET_RX_RING, unsafe.Pointer(&tp), C.socklen_t(unsafe.Sizeof(tp))); err != nil {
		return err
	} else if ret < 0 {
		return errors.New("setsockopt rx ring fail")
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

func NewHandle(ifaceName string) (*Handle, error) {
	fd, err := C.socket(C.AF_PACKET, C.SOCK_RAW, C.int(C.htons(C.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	h := &Handle{
		f: os.NewFile(uintptr(fd), ifaceName),
		frames: 128,
		framesize: int(C.getpagesize()),
	}
	if err = h.bind(ifaceName); err == nil {
		if err = h.setUpRing(); err == nil {
			return h, nil
		}
	}
	h.Close()
	return nil, err
}

func (h *Handle) ReadPacketDataTo(data []byte) (ci gopacket.CaptureInfo, err error) {
	if h.ring == nil {
		ci.CaptureLength, err = h.f.Read(data)
		ci.Timestamp = time.Now()
		return
	}
	// We're reading from the ring... scary!
	return
}

func (h *Handle) getPacketHeader() *C.struct_tpacket_hdr {

	return nil
}
