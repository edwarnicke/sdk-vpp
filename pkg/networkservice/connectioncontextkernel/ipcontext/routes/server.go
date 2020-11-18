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

// +build linux

package routes

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"

	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
)

type routesServer struct {
}

// NewServer creates a NetworkServiceServer that will put the routes from the connection context into
//  connection context into the kernel network namespace kernel interface being inserted iff the
//  selected mechanism for the connection is a kernel mechanism
//                                                       Endpoint
//  +- - - - - - - - - - - - - - - -+         +---------------------------+
//  |    kernel network namespace   |         |                           |
//                                            |                           |
//  |                               |         |                           |
//                                            |                           |
//  |                               |         |                           |
//                                            |                           |
//  |                               |         |                           |
//                        +--------- ---------+                           |
//  |                               |         |                           |
//                                            |                           |
//  |                               |         |                           |
//      routes.NewServer()                    |                           |
//  |                               |         |                           |
//                                            |                           |
//  |                               |         |                           |
//  +- - - - - - - - - - - - - - - -+         +---------------------------+
//
func NewServer() networkservice.NetworkServiceServer {
	return &routesServer{}
}

func (i *routesServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	if err := create(ctx, request.GetConnection(), metadata.IsClient(i)); err != nil {
		return nil, err
	}
	return next.Server(ctx).Request(ctx, request)
}

func (i *routesServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	// We do not have to delete routes here because the kernel deletes routes for us when we delete the interface
	return next.Server(ctx).Close(ctx, conn)
}
