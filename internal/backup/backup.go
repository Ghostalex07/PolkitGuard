package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Paths         []string `json:"paths"`
	Compress      bool     `json:"compress"`
	IncludeMeta  bool     `json:"include_meta"`
	OutputPath   string   `json:"output_path"`
	BackupDir    string   `json:"backup_dir"`
	RetentionDays int     `json:"retention_days"`
}

func NewConfig() *Config {
	return &Config{
		Paths: []string{
			"/etc/polkit-1",
			"/usr/share/polkit-1",
		},
		Compress:     true,
		IncludeMeta:  true,
		RetentionDays: 30,
		BackupDir:    "/var/backups/polkitguard",
	}
}

type Backup struct {
	Config   *Config
	Metadata BackupMetadata
}

type BackupMetadata struct {
	Timestamp    time.Time `json:"timestamp"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	PolkitVersion string   `json:"polkit_version"`
	FilesCount   int       `json:"files_count"`
	TotalSize    int64     `json:"total_size"`
}

func (b *Backup) Create() error {
	if err := os.MkdirAll(b.Config.BackupDir, 0755); err != nil {
		return err
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	backupName := fmt.Sprintf("polkitguard-backup-%s", timestamp)

	if b.Config.Compress {
		backupName += ".tar.gz"
	} else {
		backupName += ".tar"
	}

	backupPath := filepath.Join(b.Config.BackupDir, backupName)

	if b.Config.Compress {
		return b.createCompressed(backupPath)
	}

	return b.createArchive(backupPath)
}

func (b *Backup) createArchive(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	b.Metadata.Timestamp = time.Now()

	for _, basePath := range b.Config.Paths {
		if err := b.addToTar(tw, basePath); err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) createCompressed(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	b.Metadata.Timestamp = time.Now()

	for _, basePath := range b.Config.Paths {
		if err := b.addToTar(tw, basePath); err != nil {
			return err
		}
	}

	return nil
}

func (b *Backup) addToTar(tw *tar.Writer, basePath string) error {
	return filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		name := path
		if strings.HasPrefix(path, "/etc/") {
			name = strings.TrimPrefix(path, "/etc/")
		} else if strings.HasPrefix(path, "/usr/") {
			name = "usr" + strings.TrimPrefix(path, "/usr")
		}

		header, err := tar.FileInfoHeader(info, name)
		if err != nil {
			return err
		}

		header.Name = name
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.Size() > 0 {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			data, err := io.ReadAll(file)
			if err != nil {
				return err
			}

			if _, err := tw.Write(data); err != nil {
				return err
			}

			b.Metadata.FilesCount++
			b.Metadata.TotalSize += info.Size()
		}

		return nil
	})
}

func (r *Backup) Restore(backupPath string) error {
	f, err := os.Open(backupPath)
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		targetPath := "/" + header.Name
		if strings.HasPrefix(header.Name, "usr") {
			targetPath = "/usr" + strings.TrimPrefix(header.Name, "usr")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			file, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(file, tr); err != nil {
				return err
			}

			os.Chmod(targetPath, os.FileMode(header.Mode))
		}
	}

	return nil
}

func (r *Backup) List() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(r.Config.BackupDir, "polkitguard-backup-*"))
	if err != nil {
		return nil, err
	}

	return files, nil
}

func (r *Backup) CleanOld(retentionDays int) error {
	files, err := r.List()
	if err != nil {
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(file); err != nil {
				continue
			}
		}

	}

	return nil
}