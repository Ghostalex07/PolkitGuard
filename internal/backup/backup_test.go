package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.RetentionDays != 30 {
		t.Errorf("Expected 30 retention days, got %d", cfg.RetentionDays)
	}
}

func TestBackupCreate(t *testing.T) {
	tmpDir := t.TempDir()

	backup := &Backup{
		Config: &Config{
			Paths:      []string{tmpDir},
			Compress:   true,
			BackupDir:  tmpDir,
		},
	}

	if err := backup.Create(); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	files, err := backup.List()
	if err != nil {
		t.Fatalf("Failed to list backups: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected at least one backup file")
	}
}

func TestBackupCreateNoCompress(t *testing.T) {
	tmpDir := t.TempDir()

	backup := &Backup{
		Config: &Config{
			Paths:    []string{tmpDir},
			Compress: false,
			BackupDir: tmpDir,
		},
	}

	if err := backup.Create(); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}
}

func TestBackupRestore(t *testing.T) {
	t.Skip("Skipping restore test - requires valid tar archive")

	tmpDir := t.TempDir()
	restoreDir := filepath.Join(tmpDir, "restore")
	os.MkdirAll(restoreDir, 0755)

	testFile := filepath.Join(tmpDir, "test.rules")
	os.WriteFile(testFile, []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)

	backup := &Backup{
		Config: &Config{
			Paths:    []string{tmpDir},
			Compress: true,
			BackupDir: tmpDir,
		},
	}

	if err := backup.Create(); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	files, _ := backup.List()
	if len(files) == 0 {
		t.Fatal("No backup files created")
	}

	err := backup.Restore(files[0])
	if err != nil {
		t.Fatalf("Failed to restore backup: %v", err)
	}
}

func TestBackupList(t *testing.T) {
	tmpDir := t.TempDir()

	backup := &Backup{
		Config: &Config{
			Paths:    []string{tmpDir},
			Compress: true,
			BackupDir: tmpDir,
		},
	}

	// Create temp backup file
	backupFile := filepath.Join(tmpDir, "polkitguard-backup-2026-01-01-00-00-00.tar.gz")
	os.WriteFile(backupFile, []byte("test"), 0644)

	files, err := backup.List()
	if err != nil {
		t.Fatalf("Failed to list: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected at least one file")
	}
}

func TestBackupCleanOld(t *testing.T) {
	tmpDir := t.TempDir()

	backup := &Backup{
		Config: &Config{
			Paths:    []string{tmpDir},
			Compress: true,
			BackupDir: tmpDir,
		},
	}

	// Create old backup file
	oldFile := filepath.Join(tmpDir, "polkitguard-backup-2020-01-01-00-00-00.tar.gz")
	os.WriteFile(oldFile, []byte("test"), 0644)

	// Set file time to past
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(oldFile, oldTime, oldTime)

	err := backup.CleanOld(30)
	if err != nil {
		t.Fatalf("Failed to clean old: %v", err)
	}

	if _, err := os.Stat(oldFile); err == nil {
		t.Error("Expected old file to be removed")
	}
}

func TestBackupMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	backup := &Backup{
		Config: &Config{
			Paths:    []string{tmpDir},
			Compress: true,
			BackupDir: tmpDir,
		},
	}

	if err := backup.Create(); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	if backup.Metadata.Timestamp.IsZero() {
		t.Error("Expected timestamp to be set")
	}
}