# Assignment
Question 1 whole steps

1.Build it
```
clang -O2 -g -target bpf -c xdp_drop_port.c -o xdp_drop_port.o

```
2. go file main.go

   ```

   package main

import (
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

// Auto-generated structs are nicer with bpf2go, but for demo we keep it simple.

func main() {
    iface := flag.String("iface", "eth0", "Interface to attach XDP program")
    port := flag.Uint("port", 4040, "TCP port to drop")
    objPath := flag.String("obj", "xdp_drop_port.o", "Path to compiled eBPF object")
    flag.Parse()

    spec, err := ebpf.LoadCollectionSpec(*objPath)
    if err != nil {
        log.Fatalf("loading collection spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("loading collection: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["xdp_drop_port_prog"]
    if prog == nil {
        log.Fatalf("program not found in obj")
    }

    l, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: ifIndex(*iface),
    })
    if err != nil {
        log.Fatalf("attaching XDP: %v", err)
    }
    defer l.Close()

    m := coll.Maps["port_map"]
    if m == nil {
        log.Fatalf("map not found in obj")
    }

    key := uint32(0)
    val := uint16(*port)
    if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
        log.Fatalf("map update failed: %v", err)
    }

    fmt.Printf("Attached XDP program to %s. Dropping TCP packets to port %d\n", *iface, *port)

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig
    fmt.Println("Detaching...")
}

// helper: resolve interface index from name
func ifIndex(name string) int {
    iface, err := netInterfaceByName(name)
    if err != nil {
        log.Fatalf("get iface: %v", err)
    }
    return iface.Index
}

func netInterfaceByName(name string) (*net.Interface, error) {
    return net.InterfaceByName(name)
}


   ```
3.go build -o dropper main.go
4.sudo ./dropper -iface eth0 -port 4040


Question 2 whole steps
1. Compile
```
clang -O2 -g -target bpf -c sock_filter.c -o sock_filter.o

```

2. We must attach this to a cgroup v2 hierarchy controlling the process. Example

```
# Enable cgroup v2 (if not already)
mount -t cgroup2 none /sys/fs/cgroup

# Create a new cgroup
mkdir /sys/fs/cgroup/ebpf_test

# Move your process (PID=1234) into it
echo 1234 > /sys/fs/cgroup/ebpf_test/cgroup.procs

# Attach eBPF program
bpftool prog load sock_filter.o /sys/fs/bpf/sock_filter
bpftool cgroup attach /sys/fs/cgroup/ebpf_test connect4 pinned /sys/fs/bpf/sock_filter

```

