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

package l2xconnect

import (
	"context"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/govpp/binapi/l2"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/trace"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-vpp/pkg/tools/ifindex"
)

func addDel(ctx context.Context, vppConn api.Connection, addDel bool) error {
	clientIfIndex, ok := ifindex.Load(ctx, true)
	if !ok {
		return nil
	}
	serverIfIndex, ok := ifindex.Load(ctx, false)
	if !ok {
		return nil
	}

	now := time.Now()
	if _, err := l2.NewServiceClient(vppConn).SwInterfaceSetL2Xconnect(ctx, &l2.SwInterfaceSetL2Xconnect{
		RxSwIfIndex: clientIfIndex,
		TxSwIfIndex: serverIfIndex,
		Enable:      addDel,
	}); err != nil {
		return errors.WithStack(err)
	}
	trace.Log(ctx).
		WithField("RxSwIfIndex", clientIfIndex).
		WithField("TxSwIfIndex", serverIfIndex).
		WithField("Enable", addDel).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetL2Xconnect").Debug("completed")

	now = time.Now()
	if _, err := l2.NewServiceClient(vppConn).SwInterfaceSetL2Xconnect(ctx, &l2.SwInterfaceSetL2Xconnect{
		RxSwIfIndex: serverIfIndex,
		TxSwIfIndex: clientIfIndex,
		Enable:      addDel,
	}); err != nil {
		return errors.WithStack(err)
	}
	trace.Log(ctx).
		WithField("RxSwIfIndex", serverIfIndex).
		WithField("TxSwIfIndex", clientIfIndex).
		WithField("Enable", addDel).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetL2Xconnect").Debug("completed")
	return nil
}
