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
	"net/url"
	"time"

	"git.fd.io/govpp.git/api"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	"github.com/edwarnicke/govpp/binapi/tapv2"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/trace"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-vpp/pkg/tools/ifindex"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/link"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/netlinkhandle"
)

func create(ctx context.Context, conn *networkservice.Connection, vppConn api.Connection, isClient bool) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		if _, ok := ifindex.Load(ctx, isClient); ok {
			return nil
		}

		nsFilename, err := toNSFilename(mechanism)
		if err != nil {
			return err
		}

		handle, err := toNetlinkHandle(ctx, mechanism)
		if err != nil {
			return err
		}

		now := time.Now()
		tapv2Create := &tapv2.TapCreateV2{
			ID:               ^uint32(0),
			UseRandomMac:     true,
			NumRxQueues:      1,
			HostIfNameSet:    true,
			HostIfName:       linuxIfaceName(mechanism.GetInterfaceName(conn)),
			HostNamespaceSet: true,
			HostNamespace:    nsFilename,
			//TapFlags:         0, // TODO - TUN support for v3 payloads
		}
		rsp, err := tapv2.NewServiceClient(vppConn).TapCreateV2(ctx, tapv2Create)
		if err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("swIfIndex", rsp.SwIfIndex).
			WithField("HostIfName", tapv2Create.HostIfName).
			WithField("HostNamespace", tapv2Create.HostNamespace).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "TapCreateV2").Debug("completed")

		now = time.Now()
		if _, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetRxMode(ctx, &interfaces.SwInterfaceSetRxMode{
			SwIfIndex: rsp.SwIfIndex,
			Mode:      interface_types.RX_MODE_API_ADAPTIVE,
		}); err != nil {
			_, _ = tapv2.NewServiceClient(vppConn).TapDeleteV2(ctx, &tapv2.TapDeleteV2{
				SwIfIndex: rsp.SwIfIndex,
			})
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("swIfIndex", rsp.SwIfIndex).
			WithField("mode", interface_types.RX_MODE_API_ADAPTIVE).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "SwInterfaceSetRxMode").Debug("completed")

		l, err := handle.LinkByName(tapv2Create.HostIfName)
		if err != nil {
			return errors.WithStack(err)
		}
		trace.Log(ctx).
			WithField("link.Name", tapv2Create.HostIfName).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkByName").Debug("completed")

		if err := handle.LinkSetUp(l); err != nil {
			_, _ = tapv2.NewServiceClient(vppConn).TapDeleteV2(ctx, &tapv2.TapDeleteV2{
				SwIfIndex: rsp.SwIfIndex,
			})
			return errors.WithStack(err)
		}

		ifindex.Store(ctx, isClient, rsp.SwIfIndex)
		netlinkhandle.Store(ctx, isClient, handle)
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

func linuxIfaceName(ifaceName string) string {
	if len(ifaceName) <= kernel.LinuxIfMaxLength {
		return ifaceName
	}
	return ifaceName[:kernel.LinuxIfMaxLength]
}

func toNSFilename(mechanism *kernel.Mechanism) (string, error) {
	u, err := url.Parse(mechanism.GetNetNSURL())
	if err != nil {
		return "", err
	}
	if u.Scheme != kernel.NetNSURLScheme {
		return "", errors.Errorf("NetNSURL Scheme required to be %q actual %q", kernel.NetNSURLScheme, u.Scheme)
	}
	if u.Path == "" {
		return "", errors.Errorf("NetNSURL may not be empty %q", u.Path)
	}
	return u.Path, nil
}

func toNSHandle(mechanism *kernel.Mechanism) (netns.NsHandle, error) {
	filename, err := toNSFilename(mechanism)
	if err != nil {
		return 0, err
	}
	return netns.GetFromPath(filename)
}

func toNetlinkHandle(ctx context.Context, mechanism *kernel.Mechanism) (*netlink.Handle, error) {
	curNSHandle, err := netns.Get()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	nsHandle, err := toNSHandle(mechanism)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	now := time.Now()
	handle, err := netlink.NewHandleAtFrom(nsHandle, curNSHandle)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	trace.Log(ctx).
		WithField("duration", time.Since(now)).
		WithField("netlink", "NewHandleAtFrom").Debug("completed")
	return handle, nil
}
