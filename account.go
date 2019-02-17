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
	"encoding/json"
	"fmt"
	"log"
	"unsafe"
)

func GetVersion() (major byte, minor byte, patch byte) {
	var ma C.uint8_t
	var mi C.uint8_t
	var pa C.uint8_t
	C.olm_get_library_version(&ma, &mi, &pa)
	return byte(ma), byte(mi), byte(pa)
}

type IdentityKeys struct {
	Curve25519 string `json:"curve25519"`
	Ed25519    string `json:"ed25519"`
}

type OneTimeKeys struct {
	Curve25519 map[string]string `json:"curve25519"`
	Ed25519    map[string]string `json:"ed25519"`
}

type Account struct {
	buf []byte
	ptr *C.struct_OlmAccount
}

func AccountFromPickle(key string, pickle string) Account {
	account := newAccount()

	keyBufs := []byte(key)
	pickleBuffers := []byte(pickle)

	// this returns a result we should probably inspect
	C.olm_unpickle_account(
		account.ptr,
		unsafe.Pointer(&keyBufs[0]), C.size_t(len(keyBufs)),
		unsafe.Pointer(&pickleBuffers[0]), C.size_t(len(pickleBuffers)),
	)

	fmt.Println(account.lastError())

	return account
}

func newAccount() Account {
	accountBufs := make([]byte, C.olm_account_size())
	olmAccount := C.olm_account(unsafe.Pointer(&accountBufs[0]))

	return Account{buf: accountBufs, ptr: olmAccount}
}

func CreateNewAccount() Account {
	account := newAccount()
	randLen := C.olm_create_account_random_length(account.ptr)
	randBufs := make([]byte, randLen)

	_, err := rand.Read(randBufs)

	if err != nil {
		// currently we panic when we don't have enough randomness but it might
		// be better to return an error instead. however I feel like other
		// programmers might not recognize what a huge issue not having
		// randomness is so I chose the crash and burn approach
		panic(err)
	}

	fmt.Println(account.lastError())

	C.olm_create_account(account.ptr, unsafe.Pointer(&randBufs[0]), randLen)

	return account
}

func (a Account) lastError() string {
	return C.GoString(C.olm_account_last_error(a.ptr))
}

func (a Account) Pickle(key string) string {
	keyBufs := []byte(key)
	pickleBuffers := make([]byte, C.olm_pickle_account_length(a.ptr))

	// this returns a result we should probably inspect
	C.olm_pickle_account(
		a.ptr,
		unsafe.Pointer(&keyBufs[0]), C.size_t(len(keyBufs)),
		unsafe.Pointer(&pickleBuffers[0]), C.size_t(len(pickleBuffers)),
	)

	return string(pickleBuffers)
}

func (a Account) GetIdentityKeys() (IdentityKeys, error) {
	outLength := C.olm_account_identity_keys_length(a.ptr)
	outBuffers := make([]byte, outLength)
	C.olm_account_identity_keys(
		a.ptr,
		unsafe.Pointer(&outBuffers[0]), outLength,
	)
	log.Println(string(outBuffers))

	var keys IdentityKeys
	if err := json.Unmarshal(outBuffers, &keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func (a Account) Sign(message string) string {
	messageBufs := []byte(message)
	outLength := C.olm_account_signature_length(a.ptr)
	outBuffers := make([]byte, outLength)
	C.olm_account_sign(
		a.ptr,
		unsafe.Pointer(&messageBufs[0]), C.size_t(len(messageBufs)),
		unsafe.Pointer(&outBuffers[0]), outLength,
	)
	return string(outBuffers)
}

func (a Account) GetOneTimeKeys() (OneTimeKeys, error) {
	outLength := C.olm_account_one_time_keys_length(a.ptr)
	outBuffers := make([]byte, outLength)
	C.olm_account_one_time_keys(
		a.ptr,
		unsafe.Pointer(&outBuffers[0]), outLength,
	)
	var keys OneTimeKeys
	if err := json.Unmarshal(outBuffers, &keys); err != nil {
		return keys, err
	}
	return keys, nil
}

func (a Account) MarkKeysAsPublished() {
	C.olm_account_mark_keys_as_published(a.ptr)
}

func (a Account) GetMaxNumberOfOneTimeKeys() int {
	return int(C.olm_account_mark_keys_as_published(a.ptr))
}

func (a Account) GenerateOneTimeKeys(count int) {
	randLen := C.olm_account_generate_one_time_keys_random_length(
		a.ptr, C.size_t(count),
	)
	randBufs := make([]byte, randLen)

	_, err := rand.Read(randBufs)

	if err != nil {
		// currently we panic when we don't have enough randomness but it might
		// be better to return an error instead. however I feel like other
		// programmers might not recognize what a huge issue not having
		// randomness is so I chose the crash and burn approach
		panic(err)
	}

	C.olm_account_generate_one_time_keys(
		a.ptr, C.size_t(count),
		unsafe.Pointer(&randBufs[0]), randLen,
	)

	fmt.Println(a.lastError())
}
