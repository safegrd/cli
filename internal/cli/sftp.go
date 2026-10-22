package cli

import (
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/storage"
)

// resolveSFTPSecrets returns st with its SFTP password and private key read
// from their env: or file: references, on a copy of the block: the config
// itself keeps the references, so a config written back to disk never
// carries the secrets they name.
func resolveSFTPSecrets(st config.StorageConfig) (config.StorageConfig, error) {
	if st.Type != config.StorageTypeSFTP || st.SFTP == nil {
		return st, nil
	}
	s := *st.SFTP
	var err error
	if s.Password, err = resolveConfigSecret("storage.sftp.password", s.Password); err != nil {
		return st, err
	}
	if s.PrivateKey, err = resolveConfigSecret("storage.sftp.private_key", s.PrivateKey); err != nil {
		return st, err
	}
	st.SFTP = &s
	return st, nil
}

// sftpWhere names an sftp storage for messages, with no secret.
func sftpWhere(st config.StorageConfig) string {
	if st.SFTP == nil {
		return "sftp"
	}
	return st.SFTP.URL()
}

// sftpRepoStore is the repository store on an sftp storage's server, with
// keys starting at root (the host's node id, or "" for the whole directory).
func sftpRepoStore(st config.StorageConfig, root string) (*sink.SFTP, error) {
	resolved, err := resolveSFTPSecrets(st)
	if err != nil {
		return nil, err
	}
	prov, err := storage.NewSFTPStorage(resolved)
	if err != nil {
		return nil, err
	}
	return &sink.SFTP{Conn: prov.Conn(), Base: prov.Prefix(), Prefix: root}, nil
}
