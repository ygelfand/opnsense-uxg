// Package unifi renders gateway informs and maintains the adoption exchange.
package unifi

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/golang/snappy"
	"github.com/jamesbraid/unifi-emu/inform"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
)

func authKey(value string) ([]byte, error) {
	if value == "" {
		value = inform.DefaultKey
	}
	k, err := hex.DecodeString(value)
	if err != nil || len(k) != 16 {
		return nil, fmt.Errorf("invalid inform key")
	}
	return k, nil
}

// EncodePacket uses unifi-emu's TNBU v1 encoder with zlib and AES-128.
func EncodePacket(macText, keyText string, gcm bool, payload []byte) ([]byte, error) {
	mac, err := net.ParseMAC(macText)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("invalid inform MAC")
	}
	if _, err := authKey(keyText); err != nil {
		return nil, err
	}
	if keyText == "" {
		keyText = inform.DefaultKey
	}
	packet := inform.Packet{Payload: payload}
	copy(packet.MAC[:], mac)
	if gcm {
		return packet.EncodeGCM(keyText)
	}
	return packet.Encode(keyText)
}

// DecodePacket authenticates/decrypts a TNBU reply and bounds decompression.
func DecodePacket(data []byte, keyText string) ([]byte, error) {
	if len(data) < 40 || string(data[:4]) != "TNBU" {
		return nil, fmt.Errorf("invalid TNBU header")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version > 1 || binary.BigEndian.Uint32(data[32:36]) != 1 {
		return nil, fmt.Errorf("unsupported TNBU version")
	}
	n := uint64(binary.BigEndian.Uint32(data[36:40]))
	if n != uint64(len(data)-40) {
		return nil, fmt.Errorf("TNBU payload length mismatch")
	}
	flags := binary.BigEndian.Uint16(data[14:16])
	if flags & ^uint16(15) != 0 || flags&8 != 0 && flags&1 == 0 || flags&6 == 6 {
		return nil, fmt.Errorf("unsupported TNBU flags %d", flags)
	}
	body := append([]byte{}, data[40:]...)
	if flags&1 != 0 {
		key, err := authKey(keyText)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if flags&8 != 0 {
			aead, err := cipher.NewGCMWithNonceSize(block, 16)
			if err != nil {
				return nil, err
			}
			body, err = aead.Open(nil, data[16:32], body, data[:40])
			if err != nil {
				return nil, fmt.Errorf("authenticate inform response: %w", err)
			}
		} else {
			if len(body) == 0 || len(body)%aes.BlockSize != 0 {
				return nil, fmt.Errorf("invalid CBC length")
			}
			cipher.NewCBCDecrypter(block, data[16:32]).CryptBlocks(body, body)
			pad := int(body[len(body)-1])
			if pad < 1 || pad > aes.BlockSize || !bytes.Equal(body[len(body)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
				return nil, fmt.Errorf("invalid CBC padding")
			}
			body = body[:len(body)-pad]
		}
	}
	if flags&4 != 0 {
		size, err := snappy.DecodedLen(body)
		if err != nil || size > transport.MaxBody {
			return nil, fmt.Errorf("invalid or oversized snappy response")
		}
		return snappy.Decode(nil, body)
	}
	if flags&2 != 0 {
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer func() { _ = r.Close() }() // Decompressor cleanup.
		return transport.ReadBody(r)
	}
	if len(body) > transport.MaxBody {
		return nil, fmt.Errorf("decoded inform exceeds body limit")
	}
	return body, nil
}
