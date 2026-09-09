package process

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/winiphlpapi"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func requireNSI(t *testing.T) {
	t.Helper()
	require.NoError(t, winiphlpapi.LoadExtendedTable())
	available, err := nsiStatus()
	if !available {
		t.Skip("NSI keyed lookup unavailable: ", err)
	}
}

// dialLoopback returns a connection this process owns, plus its 4-tuple.
func dialLoopback(t *testing.T) (netip.AddrPort, netip.AddrPort) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		<-done
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	require.NoError(t, err)
	return local, remote
}

func TestNSIProbe(t *testing.T) {
	require.NoError(t, winiphlpapi.LoadExtendedTable())
	available, err := nsiStatus()
	t.Log("available:", available, "error:", err)
	if !available {
		t.Skip("NSI keyed lookup unavailable on this host")
	}
	require.NoError(t, err)
}

func TestNSIOwnConnection(t *testing.T) {
	requireNSI(t)
	local, remote := dialLoopback(t)
	pid, err := nsiFindPidTCP(local, remote)
	require.NoError(t, err)
	require.Equal(t, windows.GetCurrentProcessId(), pid)
}

func TestNSIAbsentConnectionIsAMiss(t *testing.T) {
	requireNSI(t)
	_, err := nsiFindPidTCP(
		netip.MustParseAddrPort("127.0.0.1:1"),
		netip.MustParseAddrPort("127.0.0.1:2"),
	)
	require.Error(t, err)
}

// TestNSIMatchesTable is the correctness gate: every live IPv4 connection must resolve
// to the same owner through the keyed read as through the public table.
func TestNSIMatchesTable(t *testing.T) {
	requireNSI(t)
	table, err := winiphlpapi.GetExtendedTcpTable()
	require.NoError(t, err)
	require.NotEmpty(t, table)

	var checked, missing int
	for _, row := range table {
		local := netip.AddrPortFrom(winiphlpapi.DwordToAddr(row.DwLocalAddr), winiphlpapi.DwordToPort(row.DwLocalPort))
		remote := netip.AddrPortFrom(winiphlpapi.DwordToAddr(row.DwRemoteAddr), winiphlpapi.DwordToPort(row.DwRemotePort))
		if !local.IsValid() || local.Port() == 0 || !remote.IsValid() || remote.Port() == 0 {
			continue
		}
		pid, lookupErr := nsiFindPidTCP(local, remote)
		if lookupErr != nil {
			// The connection may have closed between the snapshot and the lookup.
			missing++
			continue
		}
		require.Equalf(t, row.DwOwningPid, pid, "owner mismatch for %s -> %s", local, remote)
		checked++
	}
	t.Logf("verified %d connections, %d no longer present", checked, missing)
	require.Greater(t, checked, 0)
	require.Lessf(t, missing*10, checked, "too many keyed lookups missed: %d of %d", missing, checked+missing)
}

func TestFindPidPrefersNSIAndFallsBack(t *testing.T) {
	requireNSI(t)
	local, remote := dialLoopback(t)

	viaNSI, err := findPid("tcp", local, remote)
	require.NoError(t, err)
	require.Equal(t, windows.GetCurrentProcessId(), viaNSI)

	// Without a peer there is no key, so this must take the table-scan path.
	viaTable, err := findPid("tcp", local, netip.AddrPort{})
	require.NoError(t, err)
	require.Equal(t, viaNSI, viaTable)
}

func TestProcessPathCache(t *testing.T) {
	searcher, err := NewSearcher(Config{})
	require.NoError(t, err)
	defer searcher.Close()

	self := windows.GetCurrentProcessId()
	direct, err := getProcessPath(self)
	require.NoError(t, err)
	require.NotEmpty(t, direct)

	windowsSearcher := searcher.(*windowsSearcher)
	for i := 0; i < 3; i++ {
		cached, pathErr := windowsSearcher.processPathOf(self)
		require.NoError(t, pathErr)
		require.Equal(t, direct, cached)
	}
	require.Equal(t, 1, windowsSearcher.processPath.Len())

	searcher.ResetCache()
	require.Equal(t, 0, windowsSearcher.processPath.Len())
}

func TestFindProcessInfoEndToEnd(t *testing.T) {
	requireNSI(t)
	searcher, err := NewSearcher(Config{})
	require.NoError(t, err)
	defer searcher.Close()

	local, remote := dialLoopback(t)
	owner, err := searcher.FindProcessInfo(t.Context(), "tcp", local, remote)
	require.NoError(t, err)
	require.Equal(t, windows.GetCurrentProcessId(), owner.ProcessID)
	require.NotEmpty(t, owner.ProcessPath)
}

func BenchmarkFindPidNSI(b *testing.B) {
	if available, _ := nsiStatus(); !available {
		b.Skip("NSI keyed lookup unavailable")
	}
	local, remote := benchConn(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := nsiFindPidTCP(local, remote); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindPidTableScan(b *testing.B) {
	require.NoError(b, winiphlpapi.LoadExtendedTable())
	local, _ := benchConn(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := winiphlpapi.FindPid("tcp", local); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessPathUncached(b *testing.B) {
	self := windows.GetCurrentProcessId()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := getProcessPath(self); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessPathCached(b *testing.B) {
	searcher, err := NewSearcher(Config{})
	require.NoError(b, err)
	windowsSearcher := searcher.(*windowsSearcher)
	self := windows.GetCurrentProcessId()
	b.ReportAllocs()
	for b.Loop() {
		if _, err = windowsSearcher.processPathOf(self); err != nil {
			b.Fatal(err)
		}
	}
}

func benchConn(b *testing.B) (netip.AddrPort, netip.AddrPort) {
	b.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(b, err)
	b.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	b.Cleanup(func() { close(done) })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		<-done
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(b, err)
	b.Cleanup(func() { conn.Close() })
	time.Sleep(50 * time.Millisecond)
	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(b, err)
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	require.NoError(b, err)
	return local, remote
}
