package status

import (
	"context"

	"github.com/plexusone/keyforge/provider/local"
)

// LocalBackup adapts the keyring-file provider's backup state for a [Reporter].
func LocalBackup(p *local.Provider) BackupFunc {
	return func(ctx context.Context) (BackupInfo, error) {
		st, err := p.BackupStatus(ctx)
		if err != nil {
			return BackupInfo{}, err
		}
		return BackupInfo{
			Generation: st.Generation, Acknowledged: st.Acknowledged, AcknowledgedAt: st.AcknowledgedAt,
			Note: st.Note, Behind: st.Behind(), UpToDate: st.UpToDate(),
		}, nil
	}
}
