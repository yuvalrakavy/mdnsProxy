package main

import (
	"context"
	"fmt"
	"net"
	re "regexp"
	"sort"
	"time"

	"github.com/grandcat/zeroconf"
	ms "github.com/yuvalrakavy/messageStream"
)

type instanceInfo struct {
	*zeroconf.ServiceEntry
	generation int
}

type OnTerminateCallback func(browser *MDNSbrowser)

type MDNSbrowser struct {
	Service string
	Domain  string

	resolver      zeroconf.Resolver
	cycleDuration time.Duration
	generation    int

	instances      map[string]*instanceInfo
	endPoints      []*ms.EndPoint
	requestChannel chan request
	onTerminate    OnTerminateCallback
}

type request interface {
}

type AttachResult struct {
	Err              error
	InstancesElement *ms.Element
}

type attachRequest struct {
	replyChannel chan AttachResult
	endPoint     *ms.EndPoint
}

type detachRequest struct {
	replyChannel chan error
	endPoint     *ms.EndPoint
}

type terminateRequest struct {
}

var removeBackslashRegex = re.MustCompile(`\\(.)`)

func NewBrowser(resolver *zeroconf.Resolver, service, domain string, cycleDuration time.Duration, onTerminate OnTerminateCallback) *MDNSbrowser {
	browser := MDNSbrowser{
		Service:        service,
		Domain:         domain,
		resolver:       *resolver,
		cycleDuration:  cycleDuration,
		generation:     1,
		instances:      make(map[string]*instanceInfo),
		endPoints:      make([]*ms.EndPoint, 0),
		requestChannel: make(chan request, 3),
		onTerminate:    onTerminate,
	}

	go browser.run()

	return &browser
}

func (browser *MDNSbrowser) Attach(endPoint *ms.EndPoint) (*ms.Element, error) {
	replyChannel := make(chan AttachResult)
	request := attachRequest{
		replyChannel: replyChannel,
		endPoint:     endPoint,
	}

	browser.requestChannel <- request
	reply := <-replyChannel

	return reply.InstancesElement, reply.Err
}

func (browser *MDNSbrowser) Detach(endPoint *ms.EndPoint) error {
	replyChannel := make(chan error)
	r := detachRequest{
		replyChannel: replyChannel,
		endPoint:     endPoint,
	}

	browser.requestChannel <- r
	err := <-replyChannel

	return err
}

func (browser *MDNSbrowser) Terminate() {
	browser.requestChannel <- terminateRequest{}
}

func (browser *MDNSbrowser) run() {

	for {
		continueBrowsing := browser.runCycle() // Will return after timeout (cycle duration)

		if !continueBrowsing {
			break
		}

		for instanceName, instance := range browser.instances {
			// Check if entry was not seen in last scan for X generations
			// if this is the case it is removed
			if browser.generation-instance.generation >= 1 {
				browser.send("InstanceRemoved", instance, ms.Attributes{"Gracefully": false})
				delete(browser.instances, instanceName)
			}
		}

		browser.generation += 1
	}

	if browser.onTerminate != nil {
		browser.onTerminate(browser)
	}
}

func (browser *MDNSbrowser) runCycle() bool {
	browserResultChannel := make(chan *zeroconf.ServiceEntry)

	cycleCtx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		<-cycleCtx.Done()
	}()

	resolver, err := zeroconf.NewResolver()
	if err == nil {
		err = resolver.Browse(cycleCtx, browser.Service, browser.Domain, browserResultChannel)
	}

	if err != nil {
		panic(fmt.Sprintf("Browser error: %v", err))
	} else {
		for {
			select {
			case <-time.After(browser.cycleDuration):
				return true // end of cycle, but continue browsing

			case entry := <-browserResultChannel:
				anInstanceInfo, found := browser.instances[entry.Instance]

				if found {
					if entry.TTL == 0 {
						browser.send("InstanceRemoved", anInstanceInfo, ms.Attributes{"Gracefully": true})
						delete(browser.instances, entry.Instance)
					} else {
						anInstanceInfo.generation = browser.generation

						updated := false
						if entry.Port != anInstanceInfo.ServiceEntry.Port {
							updated = true
						} else if !isSameAddress(entry, anInstanceInfo.ServiceEntry) {
							updated = true
						} else if !isSameTxt(entry, anInstanceInfo.ServiceEntry) {
							updated = true
						}

						if updated {
							anInstanceInfo.ServiceEntry = entry
							browser.send("InstanceModified", anInstanceInfo)
						}
					}
				} else {
					instanceInfo := instanceInfo{entry, browser.generation}
					browser.instances[entry.Instance] = &instanceInfo
					browser.send("InstanceAdded", &instanceInfo)
				}

			case r := <-browser.requestChannel:
				switch request := r.(type) {
				case terminateRequest:
					return false // Stop browsing

				case attachRequest:
					found := false

					for _, e := range browser.endPoints {
						if e == request.endPoint {
							found = true
							break
						}
					}

					if !found {
						browser.endPoints = append(browser.endPoints, request.endPoint)
						instanceElements := make([]*ms.Element, 0, len(browser.instances))

						for _, instanceInfo := range browser.instances {
							instanceElements = append(instanceElements, instanceInfo.element())
						}

						instancesElement := ms.NewElement("Instances", instanceElements)
						request.replyChannel <- AttachResult{
							InstancesElement: instancesElement,
							Err:              nil,
						}
					} else {
						request.replyChannel <- AttachResult{Err: fmt.Errorf("Endpoint %v is aleady attached to browser for service %v.%v", request.endPoint, browser.Service, browser.Domain)}
					}

				case detachRequest:
					found := false

					for atIndex, e := range browser.endPoints {
						if e == request.endPoint {
							// Remove the end point
							browser.endPoints[atIndex] = browser.endPoints[len(browser.endPoints)-1]
							browser.endPoints = browser.endPoints[:len(browser.endPoints)-1]
							found = true
							break
						}
					}

					if found {
						if len(browser.endPoints) == 0 {
							// No more endpoint are attached, terminate browser
							// TODO: leave the browser active for a given amount of time
							browser.requestChannel <- terminateRequest{}
						}
						request.replyChannel <- nil
					} else {
						request.replyChannel <- fmt.Errorf("Endpoint %v not attached", request.endPoint)
					}
				}

			}

		}
	}
}

func (browser *MDNSbrowser) send(messageType string, instance *instanceInfo, content ...interface{}) {
	for _, endPoint := range browser.endPoints {
		_ = endPoint.Message(ms.Attributes{"Type": messageType, "Service": browser.Service, "Domain": browser.Domain}, instance.element(), content).Send()
	}

}

func (instance *instanceInfo) element() *ms.Element {
	entry := instance.ServiceEntry

	return ms.NewElement("Instance",
		ms.Attributes{
			"Name":     removeBackslashRegex.ReplaceAllString(entry.Instance, "$1"),
			"HostName": entry.HostName,
			"Port":     entry.Port,
		},
		txtElements(entry),
		ipv4Elements(entry),
		ipv6Elements(entry),
	)
}

func txtElements(entry *zeroconf.ServiceEntry) []*ms.Element {
	var elements []*ms.Element

	for _, txt := range entry.Text {
		elements = append(elements, ms.NewElement("Txt", txt))
	}

	return elements
}

func ipv4Elements(entry *zeroconf.ServiceEntry) []*ms.Element {
	var elements []*ms.Element

	for _, address := range entry.AddrIPv4 {
		elements = append(elements, ms.NewElement("IPv4", ms.Attributes{"Address": address.String()}))
	}

	return elements
}

func ipv6Elements(entry *zeroconf.ServiceEntry) []*ms.Element {
	var elements []*ms.Element

	for _, address := range entry.AddrIPv6 {
		elements = append(elements, ms.NewElement("IPv6", ms.Attributes{"Address": address.String()}))
	}

	return elements
}

func compareAddresses(a1, a2 []net.IP) bool {
	if len(a1) != len(a2) {
		return false
	}

	a1data := make([]string, len(a1))
	for i, a := range a1 {
		a1data[i] = a.String()
	}

	sort.Strings(a1data)

	a2data := make([]string, len(a1))
	for i, a := range a2 {
		a2data[i] = a.String()
	}

	sort.Strings(a1data)

	for i, d := range a1data {
		if a2data[i] != d {
			return false
		}
	}

	return true
}

func isSameAddress(e1, e2 *zeroconf.ServiceEntry) bool {
	return compareAddresses(e1.AddrIPv4, e2.AddrIPv4) && compareAddresses(e1.AddrIPv6, e2.AddrIPv6)
}

func compareTxts(t1, t2 []string) bool {
	if len(t1) != len(t2) {
		return false
	}

	var t1data, t2data []string
	copy(t1data, t1)
	copy(t2data, t2)
	sort.Strings(t1data)
	sort.Strings(t2data)

	for i, s := range t1data {
		if t2data[i] != s {
			return false
		}
	}

	return true
}

func isSameTxt(e1, e2 *zeroconf.ServiceEntry) bool {
	return compareTxts(e1.Text, e2.Text)
}
