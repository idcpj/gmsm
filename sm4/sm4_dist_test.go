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

package sm4

import (
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	type args struct {
		src []byte
		key []byte
	}
	tests := []struct {
		name string
		args args
		err  error
		dst  string
	}{
		{
			name: "simple zeropadding",
			args: args{
				src: []byte("AAAAAAAAAAAAAAAA"),
				key: []byte("BBBBBBBBBBBBBBBB"),
			},
			err: nil,
			dst: "GJewTAYGL429MjtKdiuVdQ==",
		},
		{
			name: "simple zeropadding1",
			args: args{
				src: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				key: []byte("BBBBBBBBBBBBBBBB"),
			},
			err: nil,
			dst: "GJewTAYGL429MjtKdiuVdRiXsEwGBi+NvTI7SnYrlXU=",
		},
		{
			name: "simple zeropadding1",
			args: args{
				src: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				key: []byte("BBBBBBBBBBBBBBBB"),
			},
			err: nil,
			dst: "GJewTAYGL429MjtKdiuVdRiXsEwGBi+NvTI7SnYrlXXPGeJ/NIhrFDynLX5h1vCD",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, dst := Encrypt(tt.args.src, tt.args.key)
			if !reflect.DeepEqual(err, tt.err) {
				t.Errorf("Encrypt() err = %v, err %v", err, tt.dst)
			}
			if dst != tt.dst {
				t.Errorf("Encrypt() dst = %v, err %v", dst, tt.dst)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		src string
		key []byte
	}
	tests := []struct {
		name string
		args args
		err  error
		dst  []byte
	}{
		{
			name: "simple decrypt",
			args: args{
				src: "GJewTAYGL429MjtKdiuVdRiXsEwGBi+NvTI7SnYrlXXPGeJ/NIhrFDynLX5h1vCD",
				key: []byte("BBBBBBBBBBBBBBBB"),
			},
			err: nil,
			dst: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, dst := Decrypt(tt.args.src, tt.args.key)
			if !reflect.DeepEqual(err, tt.err) {
				t.Errorf("Decrypt() err = %v, err %v", err, tt.err)
			}
			if !reflect.DeepEqual(dst, tt.dst) {
				t.Errorf("Decrypt() dst = %v, err %v", dst, tt.dst)
			}
		})
	}
}
