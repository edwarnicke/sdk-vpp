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

package ipaddress

import (
	"context"

	"git.fd.io/govpp.git/api"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
)

type ipaddressClient struct {
	vppConn api.Connection
}

// NewClient creates a NetworkServiceClient chain element to set the ip address on a vpp interface
// It sets the IP Address on the *vpp* side of an interface leaving the
// Endpoint.
//                                         Endpoint
//                              +---------------------------+
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |      ipaddress.NewClient()+-------------------+
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              |                           |
//                              +---------------------------+
//
func NewClient(vppConn api.Connection) networkservice.NetworkServiceClient {
	return &ipaddressClient{
		vppConn: vppConn,
	}
}

func (i *ipaddressClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}
	if err := addDel(ctx, conn, i.vppConn, metadata.IsClient(i), true); err != nil {
		_, _ = i.Close(ctx, conn, opts...)
		return nil, err
	}
	return conn, nil
}

func (i *ipaddressClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	return next.Client(ctx).Close(ctx, conn, opts...)
}
