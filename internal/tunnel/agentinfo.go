/*
 * Copyright 2022 OpsMx, Inc.
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

package tunnel

type AgentInfo struct {
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

func (ai *AgentInfo) ToPB() *AgentInformation {
	return &AgentInformation{
		Description: ai.Description,
	}
}

func AgentInfoFromPB(p *AgentInformation) AgentInfo {
	if p == nil {
		return AgentInfo{}
	}
	return AgentInfo{
		Description: p.Description,
	}
}
