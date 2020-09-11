package main

import (
	ctx "context"
	"fmt"
	"net"

	"github.com/grandcat/zeroconf"

	ms "github.com/yuvalrakavy/messageStream"
)

func startPublishInstance(endPoint *ms.EndPoint, context ctx.Context, name, service, domain string, instanceElement *ms.Element, defaultRemoteAddr net.Addr) error {
	fullName := name + ":" + service + "." + domain
	port := instanceElement.GetIntAttribute("Port", -1)

	if port < 0 {
		return fmt.Errorf("StartPublish of %v missing Port attribute", fullName)
	}

	host := instanceElement.GetAttribute("HostName", name)

	var ips []string

	for _, addrElement := range instanceElement.GetChildren("IPv4") {
		addr := addrElement.GetAttribute("Address", "")
		if addr == "" {
			return fmt.Errorf("StartPublish: %v missing Address attribute", fullName)
		}

		ips = append(ips, addr)
	}

	for _, addrElement := range instanceElement.GetChildren("IPv6") {
		addr := addrElement.GetAttribute("Address", "")
		if addr == "" {
			return fmt.Errorf("StartPublish: %v missing Address attribute", fullName)
		}

		ips = append(ips, addr)
	}

	var txt []string

	for _, txtElement := range instanceElement.GetChildren("Txt") {
		txt = append(txt, txtElement.GetValue())
	}

	publishLocalHost := false

	if len(ips) == 0 {
		host, _, err := net.SplitHostPort(defaultRemoteAddr.String())
		if err != nil {
			return err
		}

		if host == "127.0.0.1" || host == "[::1]" {
			publishLocalHost = true
		} else {
			ips = append(ips, host)
		}
	}

	var server *zeroconf.Server
	var err error

	if publishLocalHost {
		endPoint.Log(LogMdnsProxy).Printf("Publish %v:%v running on local machine\n", fullName, port)
		server, err = zeroconf.Register(name, service, domain, port, txt, nil)
	} else {
		endPoint.Log(LogMdnsProxy).Printf("Publish %v:%v running on another machine address %v\n", fullName, port, ips)
		server, err = zeroconf.RegisterProxy(name, service, domain, port, host, ips, txt, nil)
	}

	if err != nil {
		return fmt.Errorf("Register of %v, failed: %v", fullName, err.Error())
	}

	go func() {
		<-context.Done()
		endPoint.Log(LogMdnsProxy).Printf("Stop publishing %v:%v\n", fullName, port)
		server.Shutdown()
	}()

	return nil
}
