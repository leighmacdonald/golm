package golm

/*
#cgo LDFLAGS: -lolm -L./olm/build
#cgo CFLAGS: -I./olm/include
#include <olm/olm.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

const (
	messageTypePreKey     = iota
	olmMessageTypeMessage = iota
)

type Session struct {
	buf []byte
	ptr *C.struct_OlmSession
}

func newSession() Session {
	sessionBufs := make([]byte, C.olm_session_size())
	fmt.Printf("Created buf at %p\n", sessionBufs)
	olmSession := C.olm_session(unsafe.Pointer(&sessionBufs[0]))
	fmt.Printf("New session: %#v at %v\n", olmSession, &olmSession)

	return Session{buf: sessionBufs, ptr: olmSession}
}

func CreateOutboundSession(account Account, theirIdentityKey string, theirOneTimeKey string) Session {
	session := newSession()

	randomLength := C.olm_create_outbound_session_random_length(session.ptr)
	randomBuffers := make([]byte, randomLength)

	_, err := rand.Read(randomBuffers)

	if err != nil {
		// currently we panic when we don't have enough randomness but it
		// might be better to return an error instead. however I feel like
		// other programmers might not recognize what a huge issue not having
		// randomness is so I chose the crash and burn approach
		panic(err)
	}

	identityKeyBuffers := []byte(theirIdentityKey)
	oneTimeKeyBuffers := []byte(theirOneTimeKey)

	C.olm_create_outbound_session(
		session.ptr, account.ptr,
		unsafe.Pointer(&identityKeyBuffers[0]),
		C.size_t(len(identityKeyBuffers)),
		unsafe.Pointer(&oneTimeKeyBuffers[0]),
		C.size_t(len(oneTimeKeyBuffers)),
		unsafe.Pointer(&randomBuffers[0]), randomLength,
	)

	return session
}

func CreateInboundSession(account Account, oneTimeKeyMessage string) Session {
	session := newSession()

	oneTimeKeyMessageBuffers := []byte(oneTimeKeyMessage)

	C.olm_create_inbound_session(
		session.ptr,
		account.ptr,
		unsafe.Pointer(&oneTimeKeyMessageBuffers[0]),
		C.size_t(len(oneTimeKeyMessageBuffers)),
	)

	return session
}

func CreateInboundSessionFrom(account Account, theirIdentityKey string, oneTimeKeyMessage string) Session {
	session := newSession()
	oneTimeKeyMessageBuffers := []byte(oneTimeKeyMessage)

	C.olm_create_inbound_session(
		session.ptr,
		account.ptr,
		unsafe.Pointer(&oneTimeKeyMessageBuffers[0]),
		C.size_t(len(oneTimeKeyMessageBuffers)),
	)

	return session
}

func SessionFromPickle(key string, pickle string) Session {
	session := newSession()

	keyBufs := []byte(key)
	pickleBuffers := []byte(pickle)

	// this returns a result we should probably inspect
	C.olm_unpickle_session(
		session.ptr,
		unsafe.Pointer(&keyBufs[0]), C.size_t(len(keyBufs)),
		unsafe.Pointer(&pickleBuffers[0]), C.size_t(len(pickleBuffers)),
	)

	fmt.Println(session.lastError())

	return session
}

func (s Session) lastError() string {
	return C.GoString(C.olm_session_last_error(s.ptr))
}

func (s Session) Pickle(key string) string {
	keyBufs := []byte(key)
	pickleBuffer := make([]byte, C.olm_pickle_session_length(s.ptr))

	// this returns a result we should probably inspect
	C.olm_pickle_session(
		s.ptr,
		unsafe.Pointer(&keyBufs[0]), C.size_t(len(keyBufs)),
		unsafe.Pointer(&pickleBuffer[0]), C.size_t(len(pickleBuffer)),
	)

	return string(pickleBuffer)
}

func (s Session) GetSessionID() {
	idLength := C.olm_session_id_length(s.ptr)
	idBuffer := make([]byte, idLength)
	C.olm_session_id(s.ptr, unsafe.Pointer(&idBuffer[0]), idLength)
}

func (s Session) Encrypt(plaintext string) (int, string) {
	randomLength := C.olm_encrypt_random_length(s.ptr)
	randomBuffer := []byte{0}

	if randomLength > 0 {
		randomBuffer = make([]byte, randomLength)

		_, err := rand.Read(randomBuffer)

		if err != nil {
			// currently we panic when we don't have enough randomness but it might
			// be better to return an error instead. however I feel like other
			// programmers might not recognize what a huge issue not having
			// randomness is so I chose the crash and burn approach
			panic(err)
		}
	}

	plaintextBuffer := []byte(plaintext)

	messageType := C.olm_encrypt_message_type(s.ptr)
	messageLength := C.olm_encrypt_message_length(
		s.ptr, C.size_t(len(plaintextBuffer)),
	)
	messageBuffer := make([]byte, messageLength)

	C.olm_encrypt(
		s.ptr,
		unsafe.Pointer(&plaintextBuffer[0]),
		C.size_t(len(plaintextBuffer)),
		unsafe.Pointer(&randomBuffer[0]), randomLength,
		unsafe.Pointer(&messageBuffer[0]), messageLength,
	)

	return int(messageType), string(messageBuffer)
}

func (s Session) Decrypt(messageType int, message string) string {
	messageBuffer := []byte(message)
	maxPlaintextLength := C.olm_decrypt_max_plaintext_length(
		s.ptr, C.size_t(messageType),
		unsafe.Pointer(&messageBuffer[0]), C.size_t(len(messageBuffer)),
	)

	messageBuffer = []byte(message)
	plaintextBuffer := make([]byte, maxPlaintextLength)
	plaintextLength := C.olm_decrypt(
		s.ptr, C.size_t(messageType),
		unsafe.Pointer(&messageBuffer[0]), C.size_t(len(messageBuffer)),
		unsafe.Pointer(&plaintextBuffer[0]), maxPlaintextLength,
	)

	return string(plaintextBuffer[:plaintextLength])
}

func (s Session) matchesInbound(oneTimeKeyMessage string) bool {
	oneTimeKeyMessageBuffer := []byte(oneTimeKeyMessage)

	result := C.olm_matches_inbound_session(
		s.ptr,
		unsafe.Pointer(&oneTimeKeyMessageBuffer[0]),
		C.size_t(len(oneTimeKeyMessageBuffer)),
	)

	return result != 0
}

func (s Session) matchesInboundFrom(theirIdentityKey string, oneTimeKeyMessage string) bool {
	identityKeyBuffer := []byte(theirIdentityKey)
	oneTimeKeyMessageBuffer := []byte(oneTimeKeyMessage)
	result := C.olm_matches_inbound_session_from(
		s.ptr,
		unsafe.Pointer(&identityKeyBuffer[0]),
		C.size_t(len(identityKeyBuffer)),
		unsafe.Pointer(&oneTimeKeyMessageBuffer[0]),
		C.size_t(len(oneTimeKeyMessageBuffer)),
	)
	return result != 0
}
