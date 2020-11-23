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

package kerneltap

import (
	"context"
	"fmt"
	"time"

	"git.fd.io/govpp.git/api"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	"github.com/edwarnicke/govpp/binapi/tapv2"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/trace"

	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-vpp/pkg/tools/ifindex"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/link"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/mechutils"
)

func create(ctx context.Context, conn *networkservice.Connection, vppConn api.Connection, isClient bool) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		if _, ok := ifindex.Load(ctx, isClient); ok {
			return nil
		}

		nsFilename, err := mechutils.ToNSFilename(mechanism)
		if err != nil {
			return err
		}

		// Naming is tricky.  We want to name based on either the next or prev connection id depending on whether we
		// are on the client or server side.  Since this chain element is designed for use in a Forwarder,
		// if we are on the client side, we want to name based on the connection id from the NSE that is Next
		// if we are not the client, we want to name for the connection of of the client addressing us, which is Prev
		namingConn := conn.Clone()
		namingConn.Id = namingConn.GetPrevPathSegment().GetId()
		if isClient {
			namingConn.Id = namingConn.GetNextPathSegment().GetId()
		}

		now := time.Now()
		tapCreateV2 := &tapv2.TapCreateV2{
			ID:               ^uint32(0),
			UseRandomMac:     true,
			NumRxQueues:      1,
			TxRingSz:         1024,
			RxRingSz:         1024,
			HostIfNameSet:    true,
			HostIfName:       mechanism.GetInterfaceName(namingConn),
			HostNamespaceSet: true,
			HostNamespace:    nsFilename,
			//TapFlags:         0, // TODO - TUN support for v3 payloads
		}
		rsp, err := tapv2.NewServiceClient(vppConn).TapCreateV2(ctx, tapCreateV2)
		if err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("swIfIndex", rsp.SwIfIndex).
			WithField("HostIfName", tapCreateV2.HostIfName).
			WithField("HostNamespace", tapCreateV2.HostNamespace).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "TapCreateV2").Debug("completed")
		ifindex.Store(ctx, isClient, rsp.SwIfIndex)

		now = time.Now()
		if _, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetRxMode(ctx, &interfaces.SwInterfaceSetRxMode{
			SwIfIndex: rsp.SwIfIndex,
			Mode:      interface_types.RX_MODE_API_ADAPTIVE,
		}); err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("swIfIndex", rsp.SwIfIndex).
			WithField("mode", interface_types.RX_MODE_API_ADAPTIVE).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "SwInterfaceSetRxMode").Debug("completed")

		handle, err := mechutils.ToNetlinkHandle(mechanism)
		if err != nil {
			return err
		}

		now = time.Now()
		l, err := handle.LinkByName(tapCreateV2.HostIfName)
		if err != nil {
			return errors.Wrapf(err, "unable to find hostIfName %s", tapCreateV2.HostIfName)
		}
		trace.Log(ctx).
			WithField("link.Name", tapCreateV2.HostIfName).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkByName").Debug("completed")

		alias := fmt.Sprintf("server-%s", namingConn.GetId())
		if isClient {
			alias = fmt.Sprintf("client-%s", namingConn.GetId())
		}

		// Set the Link Alias
		now = time.Now()
		if err = handle.LinkSetAlias(l, alias); err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("alias", alias).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetAlias").Debug("completed")

		// Up the link
		now = time.Now()
		err = handle.LinkSetUp(l)
		if err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetUp").Debug("completed")

		link.Store(ctx, isClient, l)
	}
	return nil
}

func del(ctx context.Context, conn *networkservice.Connection, vppConn api.Connection, isClient bool) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		swIfIndex, ok := ifindex.Load(ctx, isClient)
		if !ok {
			return nil
		}
		_, err := tapv2.NewServiceClient(vppConn).TapDeleteV2(ctx, &tapv2.TapDeleteV2{
			SwIfIndex: swIfIndex,
		})
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	}
	return nil
}
