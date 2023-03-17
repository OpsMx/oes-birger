/*
 * Copyright 2021-2023 OpsMx, Inc.
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

package serviceconfig

import (
	"net/http"
	"strings"

	"github.com/opsmx/oes-birger/internal/jwtutil"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
)

var mutatedHeaders = []string{"X-Spinnaker-User"}
var strippedOutgoingHeaders = []string{"Authorization"}

func containsFolded(l []string, t string) bool {
	for i := 0; i < len(l); i++ {
		if strings.EqualFold(l[i], t) {
			return true
		}
	}
	return false
}

func PBHEadersToHTTP(headers []*pb.HttpHeader, out *http.Header) error {
	for _, header := range headers {
		if jwtutil.MutationIsRegistered() && containsFolded(mutatedHeaders, header.Name) {
			// only handle the first value here as well
			value := header.Values[0]
			unmutated, err := jwtutil.UnmutateHeader([]byte(value), nil)
			if err != nil {
				return err
			}
			out.Add(header.Name, unmutated)
		} else {
			for _, value := range header.Values {
				out.Add(header.Name, value)
			}
		}
	}
	return nil
}

func HTTPHeadersToPB(headers map[string][]string) (ret []*pb.HttpHeader, err error) {
	ret = make([]*pb.HttpHeader, 0)
	for name, values := range headers {
		if jwtutil.MutationIsRegistered() && containsFolded(mutatedHeaders, name) {
			// only handle the first item in the list, which is typical here
			value := values[0]
			mutated, err := jwtutil.MutateHeader(value, nil)
			if err != nil {
				return nil, err
			}
			ret = append(ret, &pb.HttpHeader{Name: name, Values: []string{string(mutated)}})
		} else if !containsFolded(strippedOutgoingHeaders, name) {
			ret = append(ret, &pb.HttpHeader{Name: name, Values: values})
		}
	}
	return ret, nil
}
