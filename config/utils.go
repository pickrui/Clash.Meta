package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

// Check if ProxyGroups form DAG(Directed Acyclic Graph), and sort all ProxyGroups by dependency order.
// Meanwhile, record the original index in the config file.
// If loop is detected, return an error with location of loop.
func proxyGroupsDagSort(groupsConfig []map[string]any) error {
	type graphNode struct {
		indegree int
		// topological order
		topo int
		// the original data in `groupsConfig`
		data map[string]any
		// `outdegree` and `from` are used in loop locating
		outdegree int
		option    *outboundgroup.GroupCommonOption
		from      []string
	}

	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	graph := make(map[string]*graphNode)

	// Step 1.1 build dependency graph
	for _, mapping := range groupsConfig {
		option := &outboundgroup.GroupCommonOption{}
		if err := decoder.Decode(mapping, option); err != nil {
			return fmt.Errorf("ProxyGroup %s: %s", option.Name, err.Error())
		}

		groupName := option.Name
		if node, ok := graph[groupName]; ok {
			if node.data != nil {
				return fmt.Errorf("ProxyGroup %s: duplicate group name", groupName)
			}
			node.data = mapping
			node.option = option
		} else {
			graph[groupName] = &graphNode{0, -1, mapping, 0, option, nil}
		}

		for _, proxy := range option.Proxies {
			if node, ex := graph[proxy]; ex {
				node.indegree++
			} else {
				graph[proxy] = &graphNode{1, -1, nil, 0, nil, nil}
			}
		}
	}
	// Step 1.2 Topological Sort
	// topological index of **ProxyGroup**
	index := 0
	queue := make([]string, 0)
	for name, node := range graph {
		// in the beginning, put nodes that have `node.indegree == 0` into queue.
		if node.indegree == 0 {
			queue = append(queue, name)
		}
	}
	// every element in queue have indegree == 0
	for ; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		node := graph[name]
		if node.option != nil {
			index++
			groupsConfig[len(groupsConfig)-index] = node.data
			if len(node.option.Proxies) == 0 {
				delete(graph, name)
				continue
			}

			for _, proxy := range node.option.Proxies {
				child := graph[proxy]
				child.indegree--
				if child.indegree == 0 {
					queue = append(queue, proxy)
				}
			}
		}
		delete(graph, name)
	}

	// no loop is detected, return sorted ProxyGroup
	if len(graph) == 0 {
		return nil
	}

	// if loop is detected, locate the loop and throw an error
	// Step 2.1 rebuild the graph, fill `outdegree` and `from` filed
	for name, node := range graph {
		if node.option == nil {
			continue
		}

		if len(node.option.Proxies) == 0 {
			continue
		}

		for _, proxy := range node.option.Proxies {
			node.outdegree++
			child := graph[proxy]
			if child.from == nil {
				child.from = make([]string, 0, child.indegree)
			}
			child.from = append(child.from, name)
		}
	}
	// Step 2.2 remove nodes outside the loop. so that we have only the loops remain in `graph`
	queue = make([]string, 0)
	// initialize queue with node have outdegree == 0
	for name, node := range graph {
		if node.outdegree == 0 {
			queue = append(queue, name)
		}
	}
	// every element in queue have outdegree == 0
	for ; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		node := graph[name]
		for _, f := range node.from {
			graph[f].outdegree--
			if graph[f].outdegree == 0 {
				queue = append(queue, f)
			}
		}
		delete(graph, name)
	}
	// Step 2.3 report the elements in loop
	loopElements := make([]string, 0, len(graph))
	for name := range graph {
		loopElements = append(loopElements, name)
		delete(graph, name)
	}
	return fmt.Errorf("loop is detected in ProxyGroup, please check following ProxyGroups: %v", loopElements)
}

// validateDialerProxies checks if all dialer-proxy references are valid
func validateDialerProxies(proxies map[string]C.Proxy) error {
	var roots []C.Proxy
	for _, proxy := range proxies {
		if dialer := proxy.ProxyInfo().DialerProxy; dialer != "" {
			if _, exists := proxies[dialer]; !exists {
				return fmt.Errorf("proxy [%s] dialer-proxy [%s] not found", proxy.Name(), dialer)
			}
			roots = append(roots, proxy)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	graph := make(map[C.Proxy][]C.Proxy)
	pending := append([]C.Proxy(nil), roots...)
	for len(pending) > 0 {
		proxy := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, visited := graph[proxy]; visited {
			continue
		}
		var dependencies []C.Proxy
		if dialer := proxy.ProxyInfo().DialerProxy; dialer != "" {
			target, exists := proxies[dialer]
			if !exists {
				return fmt.Errorf("proxy [%s] dialer-proxy [%s] not found", proxy.Name(), dialer)
			}
			dependencies = append(dependencies, target)
		}
		if group, ok := proxy.Adapter().(outboundgroup.ProxyGroup); ok {
			dependencies = append(dependencies, group.Proxies()...)
			if fallback, ok := group.(interface{ EmptyFallback() C.Proxy }); ok {
				dependencies = append(dependencies, fallback.EmptyFallback())
			}
		}
		graph[proxy] = dependencies
		pending = append(pending, dependencies...)
	}
	const onPath, acyclic = 1, 2
	state := make(map[C.Proxy]uint8, len(graph))
	type step struct {
		proxy C.Proxy
		next  int
	}
	var path []step
	for _, root := range roots {
		if state[root] == acyclic {
			continue
		}
		path = append(path[:0], step{proxy: root})
		state[root] = onPath
		for len(path) > 0 {
			current := &path[len(path)-1]
			members := graph[current.proxy]
			if current.next == len(members) {
				state[current.proxy] = acyclic
				path = path[:len(path)-1]
				continue
			}
			next := members[current.next]
			current.next++
			if state[next] == onPath {
				return fmt.Errorf("proxy [%s] has circular dialer-proxy dependency", root.Name())
			}
			if state[next] != acyclic {
				state[next] = onPath
				path = append(path, step{proxy: next})
			}
		}
	}
	return nil
}

func verifyIP6() bool {
	if skip, _ := strconv.ParseBool(os.Getenv("SKIP_SYSTEM_IPV6_CHECK")); skip {
		return true
	}
	if iAddrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range iAddrs {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
				if addr := prefix.Addr().Unmap(); addr.Is6() && addr.IsGlobalUnicast() {
					return true
				}
			}
		}
	} else {
		// eg: Calling net.InterfaceAddrs() fails on Android SDK 30
		// https://github.com/golang/go/issues/40569
		return true // just ignore
	}
	return false
}
