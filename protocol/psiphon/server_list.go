//go:build with_psiphon

package psiphon

import (
	"context"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	psiphoncommon "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// ServerListProvider, when registered in the context, supplies a signed and compressed server list package imported into the datastore once per process.
type ServerListProvider interface {
	EmbeddedServerList() []byte
}

var (
	serverListAccess   sync.Mutex
	serverListImported bool
)

func importServerList(ctx context.Context, config *psiphon.Config, provider ServerListProvider) error {
	serverListAccess.Lock()
	defer serverListAccess.Unlock()
	if serverListImported {
		return nil
	}
	content := provider.EmbeddedServerList()
	if len(content) == 0 {
		return nil
	}
	serverList, err := psiphoncommon.ReadAuthenticatedDataPackage(content, true, config.RemoteServerListSignaturePublicKey)
	if err != nil {
		return E.Cause(err, "verify embedded server list")
	}
	err = psiphon.ImportEmbeddedServerEntries(ctx, config, "", serverList)
	if err != nil {
		return E.Cause(err, "import embedded server list")
	}
	serverListImported = true
	return nil
}
