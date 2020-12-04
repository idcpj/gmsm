/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

sm4 acceleration
modified by Jack, 2017 Oct
*/

// 原始sm4 加密没有包含 对src 数据大于16位的处理,并且没有对加密结果进行 base64,再次做封装
package sm4

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

var (
	keyLengthError        = errors.New("key length neq 16")
	EncryptError          = errors.New("sm4 encrypt Error")
	DecryptError          = errors.New("sm4 encrypt Error")
	DecryptReMainDerError = errors.New("sm4 decrypt remainder length neq 0")
)

func Encrypt(src []byte, key []byte) (error, string) {
	if len(key) != BlockSize {
		return keyLengthError, ""
	}

	src = zeroPadding(src, BlockSize)
	l := len(src) / BlockSize

	dstBytes := make([]byte, 0, len(src))
	iv := make([]byte, BlockSize)

	for i := 0; i < l; i++ {
		decrypt, err := sm4Encrypt(key, iv, src[i*BlockSize:(i+1)*BlockSize])
		if err != nil {
			return EncryptError, ""
		}
		dstBytes = append(dstBytes, decrypt...)
	}

	dst := base64.StdEncoding.EncodeToString(dstBytes)

	return nil, dst

}

func Decrypt(src string, key []byte) (error, []byte) {
	iv := make([]byte, BlockSize)

	b, err2 := base64.StdEncoding.DecodeString(src)
	if err2 != nil {
		return err2, nil
	}
	if len(b)%BlockSize != 0 {
		return DecryptReMainDerError, nil
	}

	l := len(b) / BlockSize

	var dst = make([]byte, 0, len(b))

	for i := 0; i < l; i++ {
		decrypt, err := sm4Decrypt(key, iv, b[i*BlockSize:(i+1)*BlockSize])
		if err != nil {
			return DecryptError, nil
		}
		dst = append(dst, decrypt...)
	}

	dst = zerosUnPadding(dst)
	return nil, dst
}

func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(plainText))
	blockMode.CryptBlocks(cryted, plainText)
	return cryted, nil
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	return origData, nil
}

// pkcs5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func zeroPadding(src []byte, blockSize int) []byte {
	remaining := len(src) % blockSize
	if remaining == 0 {
		return src
	} else {
		return append(src, bytes.Repeat([]byte{byte(0)}, blockSize-remaining)...)
	}
}
func zerosUnPadding(src []byte) []byte {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1]
		}
	}
}
