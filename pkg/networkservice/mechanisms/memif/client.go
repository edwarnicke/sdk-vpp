// Copyright (c) 2020 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package memif

import (
	"context"

	"git.fd.io/govpp.git/api"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/cls"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
)

type memifClient struct {
	vppConn      api.Connection
	lastSocketID *uint32
}

// NewClient provides a NetworkServiceClient chain elements that support the memif Mechanism
func NewClient(vppConn api.Connection, lastSocketID *uint32) networkservice.NetworkServiceClient {
	return &memifClient{
		vppConn:      vppConn,
		lastSocketID: lastSocketID,
	}
}

func (m *memifClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	mechanism := &networkservice.Mechanism{
		Cls:        cls.LOCAL,
		Type:       MECHANISM,
		Parameters: make(map[string]string),
	}
	request.MechanismPreferences = append(request.MechanismPreferences, mechanism)
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}
	if err := create(ctx, conn, m.vppConn, m.lastSocketID, "", metadata.IsClient(m)); err != nil {
		_, _ = m.Close(ctx, conn, opts...)
		return nil, err
	}
	return conn, nil
}

func (m *memifClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	rv, err := next.Client(ctx).Close(ctx, conn, opts...)
	if err != nil {
		return nil, err
	}
	if err := del(ctx, conn, m.vppConn, metadata.IsClient(m)); err != nil {
		return nil, err
	}
	return rv, nil
}
