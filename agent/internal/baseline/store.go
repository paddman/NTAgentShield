package baseline

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

const (
	baselineVersion  = "1"
	baselineFilename = "inventory-baseline.json"
)

type Store struct {
	path       string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type signedPayload struct {
	Version   string             `json:"version"`
	SavedAt   time.Time          `json:"saved_at"`
	Inventory inventory.Snapshot `json:"inventory"`
}

type envelope struct {
	Payload   signedPayload `json:"payload"`
	PublicKey string        `json:"public_key"`
	Signature string        `json:"signature"`
}

func New(dataDir string) (*Store, error) {
	privateKey, _, err := identity.Ensure(dataDir)
	if err != nil {
		return nil, err
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("identity private key does not expose an Ed25519 public key")
	}
	return &Store{
		path:       filepath.Join(dataDir, baselineFilename),
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (s *Store) Load() (inventory.Snapshot, bool, error) {
	content, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return inventory.Snapshot{}, false, nil
	}
	if err != nil {
		return inventory.Snapshot{}, false, fmt.Errorf("read inventory baseline: %w", err)
	}
	var item envelope
	if err := json.Unmarshal(content, &item); err != nil {
		return inventory.Snapshot{}, false, fmt.Errorf("decode inventory baseline: %w", err)
	}
	if item.Payload.Version != baselineVersion {
		return inventory.Snapshot{}, false, fmt.Errorf("unsupported inventory baseline version %q", item.Payload.Version)
	}
	publicKey, err := base64.StdEncoding.DecodeString(item.PublicKey)
	if err != nil {
		return inventory.Snapshot{}, false, fmt.Errorf("decode inventory baseline public key: %w", err)
	}
	if !ed25519.PublicKey(publicKey).Equal(s.publicKey) {
		return inventory.Snapshot{}, false, errors.New("inventory baseline signer does not match this agent identity")
	}
	signature, err := base64.StdEncoding.DecodeString(item.Signature)
	if err != nil {
		return inventory.Snapshot{}, false, fmt.Errorf("decode inventory baseline signature: %w", err)
	}
	payload, err := json.Marshal(item.Payload)
	if err != nil {
		return inventory.Snapshot{}, false, fmt.Errorf("encode inventory baseline for verification: %w", err)
	}
	if !ed25519.Verify(s.publicKey, payload, signature) {
		return inventory.Snapshot{}, false, errors.New("inventory baseline signature verification failed")
	}
	return item.Payload.Inventory, true, nil
}

func (s *Store) Save(snapshot inventory.Snapshot) error {
	item := envelope{
		Payload: signedPayload{
			Version:   baselineVersion,
			SavedAt:   time.Now().UTC(),
			Inventory: snapshot,
		},
		PublicKey: base64.StdEncoding.EncodeToString(s.publicKey),
	}
	payload, err := json.Marshal(item.Payload)
	if err != nil {
		return fmt.Errorf("encode inventory baseline payload: %w", err)
	}
	item.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, payload))
	encoded, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("encode inventory baseline: %w", err)
	}
	encoded = append(encoded, '\n')
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return fmt.Errorf("write inventory baseline: %w", err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("protect inventory baseline: %w", err)
	}
	if err := os.Rename(temporary, s.path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install inventory baseline: %w", err)
	}
	return nil
}

func SnapshotFromEvent(event model.Event) (inventory.Snapshot, error) {
	value, ok := event.Attributes["inventory"]
	if !ok {
		return inventory.Snapshot{}, errors.New("asset inventory event is missing inventory payload")
	}
	if snapshot, ok := value.(inventory.Snapshot); ok {
		return snapshot, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return inventory.Snapshot{}, fmt.Errorf("encode inventory event payload: %w", err)
	}
	var snapshot inventory.Snapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return inventory.Snapshot{}, fmt.Errorf("decode inventory event payload: %w", err)
	}
	return snapshot, nil
}
