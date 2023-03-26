/*
 * Copyright 2021 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package util is a kitchen sink.  Sorry.
package util

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func Test_httpError(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"EOF error example",
			args{err: io.EOF},
			`{"error":{"message":"Unable to process request: EOF"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpError(tt.args.err); !reflect.DeepEqual(got, []byte(tt.want)) {
				t.Errorf("httpError() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestFailRequest(t *testing.T) {
	type args struct {
		ctx  context.Context
		err  error
		code int
	}
	tests := []struct {
		name string
		args args
		want dummyWriter
	}{
		{
			"EOF error example",
			args{
				context.Background(),
				io.EOF,
				http.StatusTeapot,
			},
			dummyWriter{
				written: `{"error":{"message":"Unable to process request: EOF"}}`,
				code:    http.StatusTeapot,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dummyWriter{}
			FailRequest(tt.args.ctx, &got, tt.args.err, tt.args.code)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FailRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

type dummyWriter struct {
	written string
	code    int
}

func (d *dummyWriter) Header() http.Header {
	return http.Header{}
}

func (d *dummyWriter) Write(data []byte) (int, error) {
	d.written += string(data)
	return len(data), nil
}

func (d *dummyWriter) WriteHeader(code int) {
	d.code = code
}
