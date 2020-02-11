package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
        //"fmt"
        "strings"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type aeadTEXT struct {
	otherIV   []byte
	myIV      []byte
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

const gcmTagSize_text = 12

var _ AEAD = &aeadTEXT{}

// NewAEADAESGCM12 creates a AEAD using AES-GCM with 12 bytes tag size
func NewTEXT(otherKey []byte, myKey []byte, otherIV []byte, myIV []byte) (AEAD, error) {
	if len(myKey) != 16 || len(otherKey) != 16 || len(myIV) != 4 || len(otherIV) != 4 {
		return nil, errors.New("AES-GCM: expected 16-byte keys and 4-byte IVs")
	}
	encrypterCipher, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, err
	}
	encrypter, err := cipher.NewGCMWithTagSize(encrypterCipher, gcmTagSize_text)
	if err != nil {
		return nil, err
	}
	decrypterCipher, err := aes.NewCipher(otherKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := cipher.NewGCMWithTagSize(decrypterCipher, gcmTagSize_text)
	if err != nil {
		return nil, err
	}
	return &aeadTEXT{
		otherIV:   otherIV,
		myIV:      myIV,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (aead *aeadTEXT) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
        //liusz
        if string(src[1:4]) == "EXT" {
           //fmt.Println("****aeadAESGCM12 TEXT PLAYLOAD******")
           return src[4:],nil
        }else{
           //fmt.Println("aeadAESGCM12 NO TEXT PLAYLOAD")
           return aead.decrypter.Open(dst, aead.makeNonce(aead.otherIV, packetNumber), src, associatedData)
        }
	//return aead.decrypter.Open(dst, aead.makeNonce(aead.otherIV, packetNumber), src, associatedData)
}
//liusz

func (aead *aeadTEXT) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
        //fmt.Printf("+++++in Seal ++++%s\n",src[:20])
        //fmt.Printf("+++++in Seal ++++%d\n",packetNumber)
        //fmt.Printf("+++++in Seal ++++%x\n",src)
        //liusz
        //if packetNumber < 5 {
        var str string = string(src[:20])
        if strings.Contains(str,"SHLO"){
            //fmt.Println("aeadAESGCM12 seal")
            return aead.encrypter.Seal(dst, aead.makeNonce(aead.myIV, packetNumber), src, associatedData)
        }else{
             //fmt.Println("aeadAESGCM12.TEXT seal")
             if cap(dst) < 4+len(src) {
                dst = make([]byte, 4+len(src))
             } else {
                dst = dst[:4+len(src)]
             }
             copy(dst[4:], src)
             copy(dst,"TEXT")
             //fmt.Printf("+++++in Seal TEXT++++%x\n",dst)
             return dst
        }
	//return aead.encrypter.Seal(dst, aead.makeNonce(aead.myIV, packetNumber), src, associatedData)
}
/*
func (aead *aeadTEXT) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
        //liusz
        if packetNumber < 5 {
            return aead.encrypter.Seal(dst, aead.makeNonce(aead.myIV, packetNumber), src, associatedData)
        }else{
             //fmt.Println("aeadAESGCM12.TEXT seal")
             if cap(dst) < 4+len(src) {
                dst = make([]byte, 4+len(src))
             } else {
                dst = dst[:4+len(src)]
             }
             copy(dst[4:], src)
             copy(dst,"TEXT")
             return dst
        }
	//return aead.encrypter.Seal(dst, aead.makeNonce(aead.myIV, packetNumber), src, associatedData)
}
*/
func (aead *aeadTEXT) makeNonce(iv []byte, packetNumber protocol.PacketNumber) []byte {
	res := make([]byte, 12)
	copy(res[0:4], iv)
	binary.LittleEndian.PutUint64(res[4:12], uint64(packetNumber))
	return res
}

func (aead *aeadTEXT) Overhead() int {
	return aead.encrypter.Overhead()
}
