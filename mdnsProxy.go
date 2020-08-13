package main

// mDNSproxy - This proxy is running on a LAN and allow services running on other segments to perform mDNS lookups and register
// themselve on the local mDNS
//
// messageStream messages are used for communicating with the proxy.
//
// The following messages are used
//
// <Request Type='StartBrowsing' Service={service name} [Domain={domain=local}] />
//
// Will start or attach to browsing for a given service
// The reply for this request will include all instances that were found upto this point in time:
//
// <Reply>
//   <Instances>
//		<Instance Name={Name} HostName={Name} Port={Port}>
//			<Txt>{entry}</Txt> ...
//			<IPv4 Address={address} /> ...
//			<IPv6 Address={address} /> ...
//		</Instance>
//		...
//	</Instance>
// </Reply>
//
// The client will start receiving the following messages
//
//  	<Message Type='InstanceAdded' Service={name} Domain={name}>
//			<Instance Name={Name} HostName={Name} Port={Port}>
//				<Txt>{entry}</Txt> ...
//				<IPv4 Address={address} /> ...
//				<IPv6 Address={address} /> ...
//			</Instance>
//		</Message>
//
//  	<Message Type='InstanceRemoved' Service={name} Domain={name}>
// 			<Instance Name={name} HostName={name} Port={port}>
//				<Txt>{entry}</Txt> ...
//				<IPv4 Address={address} /> ...
//				<IPv6 Address={address} /> ...
//			</Instance>
//		</Message>
//
//		<Message Type='BrowsingError' Service={name} Domain={name} Error={description} />
//
//	<Request Type='StopBrowsing' Service={service name} [Domain={domain=local}] />
//
//  <Request Type='StartPublish' Service={service name} [Domain={domain=local}] >
// 		<Instance Name={name} HostName={name} Port={port}>
//			<Txt>{entry}</Txt> ...
//			<IPv4 Address={address} /> ...
//			<IPv6 Address={address} /> ...
//		</Instance>
//		...
//  </Request>
//
//  NOTE: If not address entries are provided, the end point source address will be used
//
//  <Request Type='StopPublish' Service={service name} [Domain={domain=local}] Name={InstanceName} />
//

import (
	ctx "context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	ms "github.com/yuvalrakavy/messageStream"
)

const CYCLE_TIME = 60 // Rescan every 60 seconds

type MdnsProxyEndPointInfo struct {
	activePublishers map[string]ctx.CancelFunc
}

type MdnsProxyServiceInfo struct {
	resolver       *zeroconf.Resolver
	activeBrowsers map[string]*MDNSbrowser
}

func getMdnsProxyServiceInfo(service *ms.Service) *MdnsProxyServiceInfo {
	info := service.Info.(MdnsProxyServiceInfo)
	return &info
}

func getMdnsProxyEndPointInfo(endPoint *ms.EndPoint) *MdnsProxyEndPointInfo {
	info := endPoint.Info.(MdnsProxyEndPointInfo)
	return &info
}

func onPacketReceived(packet *ms.Packet) {
	log.Println("Recieved packet: ", packet)

	switch packet.GetType() {

	case "_Login":
		newName := packet.Element.GetAttribute("Name", "")
		if len(newName) > 0 {
			log.Println("_Login - name set to: ", newName)
			packet.EndPoint.Name = newName
		}

		_ = packet.OptionalReply(ms.Attributes{"Name": "mDNSproxy", "Version": "1.0"}).Send()

	case "_Ping":
		_ = packet.OptionalReply().Send()

	case "StartBrowsing":
		reply, err := startBrowsing(packet)

		if err != nil {
			log.Println("StartBrowsing failed:", err)
			_ = packet.Exception(err).Send()
		} else {
			_ = reply.Send()
		}

	case "StopBrowsing":
		reply, err := stopBrowsing(packet)

		if err != nil {
			log.Println("StopBrowsing failed:", err)
			_ = packet.Exception(err).Send()
		} else {
			_ = reply.Send()
		}

	case "StartPublish":
		reply, err := startPublish(packet)

		if err != nil {
			log.Println("StartPublish failed:", err)
			_ = packet.Exception(err).Send()
		} else {
			_ = reply.Send()
		}

	case "StopPublish":
		reply, err := stopPublish(packet)

		if err != nil {
			log.Println("StopPublish failed:", err)
			_ = packet.Exception(err).Send()
		} else {
			_ = reply.Send()
		}

	default:
		log.Println("Invalid request:", packet)
		_ = packet.Exception(fmt.Errorf("Invalid request: %v", packet)).Send()
	}
}

func startBrowsing(packet *ms.Packet) (*ms.Packet, error) {
	service := packet.Element.GetAttribute("Service", "")
	if service == "" {
		return nil, fmt.Errorf("StartBrowsing: Missing Service attribute")
	}

	domain := packet.Element.GetAttribute("Domain", "local.")
	fullServiceName := service + "." + domain
	serviceInfo := getMdnsProxyServiceInfo(packet.EndPoint.Service)

	browser, alreadyBrowsing := serviceInfo.activeBrowsers[fullServiceName]
	if !alreadyBrowsing {
		browser = NewBrowser(serviceInfo.resolver, service, domain, CYCLE_TIME*time.Second, func(b *MDNSbrowser) {
			log.Println("Browser for ", fullServiceName, " was terminated")
			delete(serviceInfo.activeBrowsers, fullServiceName)
		})
		serviceInfo.activeBrowsers[fullServiceName] = browser
	}

	instancesElement, err := browser.Attach(packet.EndPoint)

	if err != nil {
		return nil, err
	} else {
		return packet.Reply(instancesElement), nil
	}
}

func stopBrowsing(packet *ms.Packet) (*ms.Packet, error) {
	service := packet.Element.GetAttribute("Service", "")
	if service == "" {
		return nil, fmt.Errorf("StopBrowsing: Missing Service attribute")
	}

	domain := packet.Element.GetAttribute("Domain", "local.")

	fullServiceName := service + "." + domain
	serviceInfo := getMdnsProxyServiceInfo(packet.EndPoint.Service)

	browser, alreadyBrowsing := serviceInfo.activeBrowsers[fullServiceName]
	if !alreadyBrowsing {
		return nil, fmt.Errorf("Service %v is not currently browsed", fullServiceName)
	} else {
		err := browser.Detach(packet.EndPoint)
		if err != nil {
			return nil, err
		} else {
			return packet.OptionalReply(), nil
		}
	}
}

func startPublish(packet *ms.Packet) (*ms.Packet, error) {
	endPointInfo := getMdnsProxyEndPointInfo(packet.EndPoint)
	service := packet.Element.GetAttribute("Service", "")
	if service == "" {
		return nil, fmt.Errorf("StartPublish: Missing Service attribute")
	}

	domain := packet.Element.GetAttribute("Domain", "local.")

	remoteEndPointAddress := packet.EndPoint.Connection.RemoteAddr()
	instanceElements := packet.Element.GetChildren("Instance")

	if len(instanceElements) == 0 {
		return nil, fmt.Errorf("StartPublish request has empty instance list (nothing to publish...)")
	}

	for _, instanceElement := range instanceElements {
		name := instanceElement.GetAttribute("Name", "")

		if name == "" {
			return nil, fmt.Errorf("StartPublish instance has no Name attribute")
		}

		fullName := name + ":" + service + "." + domain
		_, alreadyPublished := endPointInfo.activePublishers[fullName]

		if alreadyPublished {
			return nil, fmt.Errorf("StartPublish: Instance %v is already published", fullName)
		}

		context, cancel := ctx.WithCancel(ctx.Background())
		fmt.Println("RemoteEndPointAddress:", remoteEndPointAddress.String())
		err := startPublishInstance(context, name, service, domain, instanceElement, remoteEndPointAddress)

		if err != nil {
			cancel()
			return nil, fmt.Errorf("StartPublish of %v, error: %v", fullName, err.Error())
		}

		endPointInfo.activePublishers[fullName] = cancel
	}

	return packet.Reply(), nil
}

func stopPublish(packet *ms.Packet) (*ms.Packet, error) {
	endPointInfo := getMdnsProxyEndPointInfo(packet.EndPoint)
	service := packet.Element.GetAttribute("Service", "")
	if service == "" {
		return nil, fmt.Errorf("StopPublish: Missing Service attribute")
	}

	name := packet.Element.GetAttribute("Name", "")

	if name == "" {
		return nil, fmt.Errorf("StopPublish has no Name attribute")
	}

	domain := packet.Element.GetAttribute("Domain", "local.")

	fullName := name + ":" + service + "." + domain
	cancel, alreadyPublished := endPointInfo.activePublishers[fullName]

	if !alreadyPublished {
		return nil, fmt.Errorf("StopPublish: %v is not published", fullName)
	}

	cancel()
	return packet.Reply(), nil
}

func onCloseEndPoint(endPoint *ms.EndPoint) {
	info := getMdnsProxyEndPointInfo(endPoint)
	serviceInfo := getMdnsProxyServiceInfo(endPoint.Service)

	for _, browser := range serviceInfo.activeBrowsers {
		_ = browser.Detach(endPoint)
	}

	for _, cancel := range info.activePublishers {
		cancel()
	}
}

func main() {
	var err error
	var port int

	flag.IntVar(&port, "port", 1000, "service port")
	flag.Parse()

	log.Println("Starting mDNS proxy service on port:", port)

	serviceInfo := MdnsProxyServiceInfo{
		activeBrowsers: make(map[string]*MDNSbrowser),
	}

	if serviceInfo.resolver, err = zeroconf.NewResolver(); err != nil {
		panic(fmt.Errorf("Could not create zeroconf resolver: %v", err.Error()))
	}

	service := ms.NewService("mDNSproxy", "tcp", ":"+strconv.Itoa(port), serviceInfo, func(service *ms.Service, conn net.Conn) *ms.EndPoint {
		endPoint := ms.NewEndPoint("", conn).OnPacketReceived(onPacketReceived).OnClose(onCloseEndPoint)
		endPoint.Info = MdnsProxyEndPointInfo{
			activePublishers: make(map[string]ctx.CancelFunc),
		}

		return endPoint
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c

	service.Terminate()
	log.Print("mDNS proxy terminated")
}
