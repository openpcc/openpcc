// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package evidence

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-eventlog/register"
	pb "github.com/openpcc/openpcc/gen/protos/evidence"
	"google.golang.org/protobuf/proto"
)

var (
	// These are the PCRs necessary to validate the parts
	// of the event log that attest to our application
	AttestPCRSelection = []uint{
		0, 1, 2, 3,
		4, 5, 7, 8,
		12, // PCR where we store the hash of the model
	}
)

// ComputeData contains information provided to the client
// to pick a compute node and encrypt data for it.
type ComputeData struct {
	KEM       hpke.KEM
	KDF       hpke.KDF
	AEAD      hpke.AEAD
	PublicKey []byte // as marshalled by the KEM.
}

func (c *ComputeData) UnmarshalPublicKey() (kem.PublicKey, error) {
	return c.KEM.Scheme().UnmarshalBinaryPublicKey(c.PublicKey)
}

//revive:disable:exported
type EvidenceType int

//revive:enable:exported
const (
	EvidenceTypeUnspecified EvidenceType = iota
	CertifyRekCreation
	GceAkCertificate
	GceAkIntermediateCertificate
	TpmtPublic
	SevSnpReport
	TdxReport
	NvidiaETA
	NvidiaCCIntermediateCertificate
	AzureAkCertificate
	EventLog
	ImageSigstoreBundle
	TpmQuote
	TdxCollateral
	NvidiaSwitchETA
	NvidiaSwitchIntermediateCertificate
	SevSnpExtendedReport
	AkTPMTPublic
	AzureRuntimeData
)

func (s EvidenceType) String() string {
	switch s {
	case CertifyRekCreation:
		return "CertifyRekCreation"
	case GceAkCertificate:
		return "GceAkCertificate"
	case GceAkIntermediateCertificate:
		return "GceAkIntermediateCertificate"
	case TpmtPublic:
		return "TpmtPublic"
	case SevSnpReport:
		return "SevSnpReport"
	case TdxReport:
		return "TdxReport"
	case NvidiaETA:
		return "NvidiaETA"
	case NvidiaCCIntermediateCertificate:
		return "NvidiaCCIntermediateCertificate"
	case AzureAkCertificate:
		return "AzureAkCertificate"
	case EventLog:
		return "EventLog"
	case ImageSigstoreBundle:
		return "ImageSigstoreBundle"
	case TpmQuote:
		return "TpmQuote"
	case TdxCollateral:
		return "TdxCollateral"
	case NvidiaSwitchETA:
		return "NvidiaSwitchETA"
	case NvidiaSwitchIntermediateCertificate:
		return "NvidiaSwitchIntermediateCertificate"
	case SevSnpExtendedReport:
		return "SevSnpExtendedReport"
	case AkTPMTPublic:
		return "AkTPMTPublic"
	case AzureRuntimeData:
		return "AzureRuntimeData"
	case EvidenceTypeUnspecified:
		// for completeness, we must include unspecified. revive:useless-fallthrough triggers if there is no comment
		fallthrough
	default:
		return "EvidenceTypeUnspecified"
	}
}

type TEEType int

const (
	NoTEE TEEType = iota
	Tdx
	SevSnp
)

func (s EvidenceType) MarshalProto() pb.EvidenceType {
	switch s {
	case CertifyRekCreation:
		return pb.EvidenceType_EVIDENCE_TYPE_TPM_CERTIFY_REK_CREATION
	case GceAkCertificate:
		return pb.EvidenceType_EVIDENCE_TYPE_GCE_AK_CERTIFICATE
	case TpmtPublic:
		return pb.EvidenceType_EVIDENCE_TYPE_TPMT_PUBLIC
	case SevSnpReport:
		return pb.EvidenceType_EVIDENCE_TYPE_SEVSNP_REPORT
	case TdxReport:
		return pb.EvidenceType_EVIDENCE_TYPE_TDX_REPORT
	case NvidiaETA:
		return pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_ETA
	case GceAkIntermediateCertificate:
		return pb.EvidenceType_EVIDENCE_TYPE_GCE_AK_INTERMEDIATE_CERTIFICATE
	case NvidiaCCIntermediateCertificate:
		return pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_INTERMEDIATE_CERTIFICATE
	case AzureAkCertificate:
		return pb.EvidenceType_EVIDENCE_TYPE_AZURE_AK_CERTIFICATE
	case EventLog:
		return pb.EvidenceType_EVIDENCE_TYPE_EVENT_LOG
	case TpmQuote:
		return pb.EvidenceType_EVIDENCE_TYPE_TPM_QUOTE
	case ImageSigstoreBundle:
		return pb.EvidenceType_EVIDENCE_TYPE_IMAGE_SIGSTORE_BUNDLE
	case TdxCollateral:
		return pb.EvidenceType_EVIDENCE_TYPE_TDX_COLLATERAL
	case NvidiaSwitchETA:
		return pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_SWITCH_ETA
	case NvidiaSwitchIntermediateCertificate:
		return pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_SWITCH_INTERMEDIATE_CERTIFICATE
	case SevSnpExtendedReport:
		return pb.EvidenceType_EVIDENCE_TYPE_SEVSNP_EXTENDED_REPORT
	case AkTPMTPublic:
		return pb.EvidenceType_EVIDENCE_TYPE_AK_TPMT_PUBLIC
	case AzureRuntimeData:
		return pb.EvidenceType_EVIDENCE_TYPE_AZURE_CVM_RUNTIME_DATA
	case EvidenceTypeUnspecified:
		// for completeness, we must include unspecified. revive:useless-fallthrough triggers if there is no comment
		fallthrough
	default:
		return pb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED
	}
}

func (s *EvidenceType) UnmarshalProto(pbt pb.EvidenceType) error {
	switch pbt {
	case pb.EvidenceType_EVIDENCE_TYPE_TPM_CERTIFY_REK_CREATION:
		*s = CertifyRekCreation
	case pb.EvidenceType_EVIDENCE_TYPE_GCE_AK_CERTIFICATE:
		*s = GceAkCertificate
	case pb.EvidenceType_EVIDENCE_TYPE_TPMT_PUBLIC:
		*s = TpmtPublic
	case pb.EvidenceType_EVIDENCE_TYPE_SEVSNP_REPORT:
		*s = SevSnpReport
	case pb.EvidenceType_EVIDENCE_TYPE_TDX_REPORT:
		*s = TdxReport
	case pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_ETA:
		*s = NvidiaETA
	case pb.EvidenceType_EVIDENCE_TYPE_GCE_AK_INTERMEDIATE_CERTIFICATE:
		*s = GceAkIntermediateCertificate
	case pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_INTERMEDIATE_CERTIFICATE:
		*s = NvidiaCCIntermediateCertificate
	case pb.EvidenceType_EVIDENCE_TYPE_AZURE_AK_CERTIFICATE:
		*s = AzureAkCertificate
	case pb.EvidenceType_EVIDENCE_TYPE_EVENT_LOG:
		*s = EventLog
	case pb.EvidenceType_EVIDENCE_TYPE_TPM_QUOTE:
		*s = TpmQuote
	case pb.EvidenceType_EVIDENCE_TYPE_IMAGE_SIGSTORE_BUNDLE:
		*s = ImageSigstoreBundle
	case pb.EvidenceType_EVIDENCE_TYPE_TDX_COLLATERAL:
		*s = TdxCollateral
	case pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_SWITCH_ETA:
		*s = NvidiaSwitchETA
	case pb.EvidenceType_EVIDENCE_TYPE_NVIDIA_SWITCH_INTERMEDIATE_CERTIFICATE:
		*s = NvidiaSwitchIntermediateCertificate
	case pb.EvidenceType_EVIDENCE_TYPE_SEVSNP_EXTENDED_REPORT:
		*s = SevSnpExtendedReport
	case pb.EvidenceType_EVIDENCE_TYPE_AK_TPMT_PUBLIC:
		*s = AkTPMTPublic
	case pb.EvidenceType_EVIDENCE_TYPE_AZURE_CVM_RUNTIME_DATA:
		*s = AzureRuntimeData
	case pb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED:
		// for completeness, we must include unspecified. revive:useless-fallthrough triggers if there is no comment
		fallthrough
	default:
		*s = EvidenceTypeUnspecified
	}
	return nil
}

type SignedEvidencePiece struct {
	Type      EvidenceType
	Data      []byte
	Signature []byte
}

func (se *SignedEvidencePiece) Clone() *SignedEvidencePiece {
	return &SignedEvidencePiece{
		Type:      se.Type,
		Data:      bytes.Clone(se.Data),
		Signature: bytes.Clone(se.Signature),
	}
}

func (se *SignedEvidencePiece) MarshalProto() *pb.SignedEvidencePiece {
	pbsep := &pb.SignedEvidencePiece{}

	pbsep.SetType(se.Type.MarshalProto())
	pbsep.SetData(se.Data)
	pbsep.SetSignature(se.Signature)

	return pbsep
}

func (se *SignedEvidencePiece) UnmarshalProto(pbsep *pb.SignedEvidencePiece) error {
	var t EvidenceType
	err := t.UnmarshalProto(pbsep.GetType())
	if err != nil {
		return fmt.Errorf("failed to unmarshal evidence type: %w", err)
	}

	se.Type = t
	se.Data = pbsep.GetData()
	se.Signature = pbsep.GetSignature()

	return nil
}

func SignedEvidencePieceFromJWT(token *jwt.Token, evidenceType EvidenceType) (*SignedEvidencePiece, error) {
	if token == nil {
		return nil, errors.New("token is nil")
	}

	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	content := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return &SignedEvidencePiece{
		Data:      content,
		Signature: sig,
		Type:      evidenceType,
	}, nil
}

func (se *SignedEvidencePiece) ToJWT() string {
	tokenString := string(se.Data) + "." + jwtBase64Encode(se.Signature)

	return tokenString
}

func jwtBase64Encode(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

type SignedEvidenceList []*SignedEvidencePiece

func (s SignedEvidenceList) Clone() SignedEvidenceList {
	if s == nil {
		return nil
	}

	out := make(SignedEvidenceList, 0, len(s))
	for _, piece := range s {
		out = append(out, piece.Clone())
	}
	return out
}

func (s SignedEvidenceList) MarshalProto() *pb.SignedEvidenceList {
	pbsel := &pb.SignedEvidenceList{}
	list := make([]*pb.SignedEvidencePiece, 0, len(s))
	for _, sep := range s {
		list = append(list, sep.MarshalProto())
	}

	pbsel.SetItems(list)

	return pbsel
}

func (s *SignedEvidenceList) UnmarshalProto(pbsel *pb.SignedEvidenceList) error {
	items := pbsel.GetItems()
	newS := make([]*SignedEvidencePiece, 0, len(items))
	for i, item := range items {
		sep := &SignedEvidencePiece{}
		err := sep.UnmarshalProto(item)
		if err != nil {
			return fmt.Errorf("failed to unmarshal signed evidence piece %d: %w", i, err)
		}
		newS = append(newS, sep)
	}

	*s = newS
	return nil
}

func (s *SignedEvidenceList) UnmarshalBinary(data []byte) error {
	pbsel := &pb.SignedEvidenceList{}
	err := proto.Unmarshal(data, pbsel)
	if err != nil {
		return err
	}
	return s.UnmarshalProto(pbsel)
}

func (s *SignedEvidenceList) MarshalBinary() ([]byte, error) {
	return proto.Marshal(s.MarshalProto())
}

// PCRValues wraps the PCRValues proto message
type PCRValues struct {
	Values map[uint32][]byte
}

func (p *PCRValues) MarshalBinary() ([]byte, error) {
	pbpcr := p.MarshalProto()
	return proto.Marshal(pbpcr)
}

func (p *PCRValues) UnmarshalBinary(b []byte) error {
	pbv := &pb.PCRValues{}
	err := proto.Unmarshal(b, pbv)
	if err != nil {
		return err
	}

	p.Values = pbv.GetValues()
	return nil
}

func (p *PCRValues) MarshalProto() *pb.PCRValues {
	pbpcr := &pb.PCRValues{}

	values := make(map[uint32][]byte, len(p.Values))
	for k, v := range p.Values {
		values[k] = v
	}

	pbpcr.SetValues(values)
	return pbpcr
}

func (p *PCRValues) UnmarshalProto(pbpcr *pb.PCRValues) error {
	p.Values = make(map[uint32][]byte)

	for k, v := range pbpcr.GetValues() {
		p.Values[k] = v
	}

	return nil
}

// Convert to the types used by google/go-eventlog
func (p *PCRValues) ToMRs() []register.MR {
	measurementRegisters := make([]register.MR, len(p.Values))
	i := 0
	for pcrIdx, value := range p.Values {
		measurementRegisters[i] = register.PCR{
			Index:     int(pcrIdx),
			Digest:    value,
			DigestAlg: crypto.SHA256,
		}
		i++
	}
	return measurementRegisters
}

// TPMQuoteAttestation wraps the TPMQuoteAttestation proto message
type TPMQuoteAttestation struct {
	TmpstAttestQuote []byte
	PCRValues        *PCRValues
}

func (tqa *TPMQuoteAttestation) MarshalProto() *pb.TPMQuoteAttestation {
	pbtqa := &pb.TPMQuoteAttestation{}

	pbtqa.SetTpmstAttestQuote(tqa.TmpstAttestQuote)

	if tqa.PCRValues != nil {
		pbtqa.SetPcrValues(tqa.PCRValues.MarshalProto())
	}

	return pbtqa
}

func (tqa *TPMQuoteAttestation) UnmarshalProto(pbtqa *pb.TPMQuoteAttestation) error {
	tqa.TmpstAttestQuote = pbtqa.GetTpmstAttestQuote()

	if pbpcr := pbtqa.GetPcrValues(); pbpcr != nil {
		tqa.PCRValues = &PCRValues{}
		err := tqa.PCRValues.UnmarshalProto(pbpcr)
		if err != nil {
			return fmt.Errorf("failed to unmarshal PCR values: %w", err)
		}
	}

	return nil
}

func (tqa *TPMQuoteAttestation) UnmarshalBinary(data []byte) error {
	pbtqa := &pb.TPMQuoteAttestation{}
	err := proto.Unmarshal(data, pbtqa)
	if err != nil {
		return err
	}
	return tqa.UnmarshalProto(pbtqa)
}

func (tqa *TPMQuoteAttestation) MarshalBinary() ([]byte, error) {
	return proto.Marshal(tqa.MarshalProto())
}

type TDXCollateral struct {
	RootCrlBody                   []byte
	RootCrlHeaders                map[string][]string
	PckCrlBody                    []byte
	PckCrlHeaders                 map[string][]string
	PckCrlRootCertificate         *x509.Certificate
	PckCrlIntermediateCertificate *x509.Certificate
	QeBody                        []byte
	QeHeaders                     map[string][]string
	QeRootCertificate             *x509.Certificate
	QeIntermediateCertificate     *x509.Certificate
	TcbBody                       []byte
	TcbHeaders                    map[string][]string
	TcbRootCertificate            *x509.Certificate
	TcbIntermediateCertificate    *x509.Certificate
}

func (cb *TDXCollateral) MarshalProto() *pb.TDXCollateral {
	cbProto := &pb.TDXCollateral{}

	cbProto.SetRootCrlBody(cb.RootCrlBody)
	cbProto.SetRootCrlHeaders(ToResponseHeaders(cb.RootCrlHeaders))
	cbProto.SetPckCrlBody(cb.PckCrlBody)
	cbProto.SetPckCrlHeaders(ToResponseHeaders(cb.PckCrlHeaders))
	cbProto.SetPckCrlRootCertificate(cb.PckCrlRootCertificate.Raw)
	cbProto.SetPckCrlIntermediateCertificate(cb.PckCrlIntermediateCertificate.Raw)
	cbProto.SetQeBody(cb.QeBody)
	cbProto.SetQeHeaders(ToResponseHeaders(cb.QeHeaders))
	cbProto.SetQeRootCertificate(cb.QeRootCertificate.Raw)
	cbProto.SetQeIntermediateCertificate(cb.QeIntermediateCertificate.Raw)
	cbProto.SetTcbBody(cb.TcbBody)
	cbProto.SetTcbHeaders(ToResponseHeaders(cb.TcbHeaders))
	cbProto.SetTcbRootCertificate(cb.TcbRootCertificate.Raw)
	cbProto.SetTcbIntermediateCertificate(cb.TcbIntermediateCertificate.Raw)
	return cbProto
}

func (cb *TDXCollateral) UnmarshalProto(cbProto *pb.TDXCollateral) error {
	cb.RootCrlBody = cbProto.GetRootCrlBody()
	cb.RootCrlHeaders = FromResponseHeaders(cbProto.GetRootCrlHeaders())
	cb.PckCrlBody = cbProto.GetPckCrlBody()
	cb.PckCrlHeaders = FromResponseHeaders(cbProto.GetPckCrlHeaders())

	var err error
	if rawCert := cbProto.GetPckCrlRootCertificate(); len(rawCert) > 0 {
		cb.PckCrlRootCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse PckCrlRootCertificate: %w", err)
		}
	}

	if rawCert := cbProto.GetPckCrlIntermediateCertificate(); len(rawCert) > 0 {
		cb.PckCrlIntermediateCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse PckCrlIntermediateCertificate: %w", err)
		}
	}

	cb.QeBody = cbProto.GetQeBody()
	cb.QeHeaders = FromResponseHeaders(cbProto.GetQeHeaders())

	if rawCert := cbProto.GetQeRootCertificate(); len(rawCert) > 0 {
		cb.QeRootCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse QeRootCertificate: %w", err)
		}
	}

	if rawCert := cbProto.GetQeIntermediateCertificate(); len(rawCert) > 0 {
		cb.QeIntermediateCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse QeIntermediateCertificate: %w", err)
		}
	}

	cb.TcbBody = cbProto.GetTcbBody()
	cb.TcbHeaders = FromResponseHeaders(cbProto.GetTcbHeaders())

	if rawCert := cbProto.GetTcbRootCertificate(); len(rawCert) > 0 {
		cb.TcbRootCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse TcbRootCertificate: %w", err)
		}
	}

	if rawCert := cbProto.GetTcbIntermediateCertificate(); len(rawCert) > 0 {
		cb.TcbIntermediateCertificate, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse TcbIntermediateCertificate: %w", err)
		}
	}

	return nil
}

func (cb *TDXCollateral) UnmarshalBinary(data []byte) error {
	cbProto := &pb.TDXCollateral{}
	err := proto.Unmarshal(data, cbProto)
	if err != nil {
		return err
	}
	return cb.UnmarshalProto(cbProto)
}

func (cb *TDXCollateral) MarshalBinary() ([]byte, error) {
	return proto.Marshal(cb.MarshalProto())
}

func ToResponseHeaders(goMap map[string][]string) *pb.ResponseHeaders {
	entries := make([]*pb.HeaderEntry, 0, len(goMap))

	for key, values := range goMap {
		entry := &pb.HeaderEntry{}
		entry.SetKey(key)
		entry.SetValues(values)
		entries = append(entries, entry)
	}

	msg := &pb.ResponseHeaders{}
	msg.SetEntries(entries)
	return msg
}

// Convert proto message to Go map
func FromResponseHeaders(msg *pb.ResponseHeaders) map[string][]string {
	result := make(map[string][]string)

	for _, entry := range msg.GetEntries() {
		result[entry.GetKey()] = entry.GetValues()
	}

	return result
}

// Custom types with their own unmarshaling logic
type Base64Data []byte

func (b *Base64Data) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*b = nil
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}
	*b = decoded
	return nil
}

type HexData []byte

func (h *HexData) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}
	*h = decoded
	return nil
}

type AzureCVMRuntimeData struct {
	Keys                  []*AzureCVMKey         `json:"keys"`
	AzureCVMConfiguration *AzureCVMConfiguration `json:"vm-configuration"`
	UserData              HexData                `json:"user-data"`
	Signature             [32]byte
	OriginalJSON          []byte
}

type AzureCVMKey struct {
	Kid    string     `json:"kid"`
	KeyOps []string   `json:"key_ops"`
	Kty    string     `json:"kty"`
	E      Base64Data `json:"e"`
	N      Base64Data `json:"n"`
}

func (k *AzureCVMKey) ToPubKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, errors.New("not an RSA key")
	}

	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(k.N),
		E: int(big.NewInt(0).SetBytes(k.E).Int64()),
	}, nil
}

type AzureCVMConfiguration struct {
	ConsoleEnabled     bool       `json:"console-enabled"`
	RootCertThumbprint Base64Data `json:"root-cert-thumbprint"`
	SecureBoot         bool       `json:"secure-boot"`
	TpmEnabled         bool       `json:"tpm-enabled"`
	TpmPersisted       bool       `json:"tpm-persisted"`
	VmUniqueID         string     `json:"vmUniqueId"`
}

func (c *AzureCVMRuntimeData) MarshalProto() *pb.AzureCVMRuntimeData {
	message := &pb.AzureCVMRuntimeData{}

	pbKeys := []*pb.AzureCVMKey{}
	for _, key := range c.Keys {
		pbKeys = append(pbKeys, key.MarshalProto())
	}

	message.SetKeys(pbKeys)
	message.SetConfiguration(c.AzureCVMConfiguration.MarshalProto())
	message.SetOriginalJson(c.OriginalJSON)
	message.SetSignature(c.Signature[:])
	return message
}

func (c *AzureCVMRuntimeData) MarshalBinary() ([]byte, error) {
	return proto.Marshal(c.MarshalProto())
}

func (c *AzureCVMRuntimeData) UnmarshalProto(runtimeDataProto *pb.AzureCVMRuntimeData) error {
	config := &AzureCVMConfiguration{}
	config.UnmarshalProto(runtimeDataProto.GetConfiguration())
	c.AzureCVMConfiguration = config

	keys := []*AzureCVMKey{}
	for _, pbKey := range runtimeDataProto.GetKeys() {
		key := &AzureCVMKey{}
		key.UnmarshalProto(pbKey)
		keys = append(keys, key)
	}
	c.Keys = keys
	c.UserData = runtimeDataProto.GetUserData()

	if c.UserData == nil {
		// golang proto will deserialize an all null bytestring as nil, handle that case here
		c.UserData = make([]byte, 64)
	}
	c.OriginalJSON = runtimeDataProto.GetOriginalJson()
	c.Signature = [32]byte(runtimeDataProto.GetSignature())
	return nil
}

func (c *AzureCVMConfiguration) UnmarshalProto(configProto *pb.AzureCVMConfiguration) error {
	c.ConsoleEnabled = configProto.GetConsoleEnabled()
	c.RootCertThumbprint = configProto.GetRootCertThumbprint()
	c.SecureBoot = configProto.GetSecureBoot()
	c.VmUniqueID = configProto.GetVmUniqueId()
	c.TpmPersisted = configProto.GetTpmPersisted()
	c.TpmEnabled = configProto.GetTpmEnabled()

	return nil
}

func (c *AzureCVMKey) UnmarshalProto(keyProto *pb.AzureCVMKey) error {
	c.E = keyProto.GetE()
	c.N = keyProto.GetN()
	c.KeyOps = keyProto.GetKeyOps()
	c.Kid = keyProto.GetKid()
	c.Kty = keyProto.GetKty()

	return nil
}

func (c *AzureCVMRuntimeData) UnmarshalBinary(data []byte) error {
	runtimeProto := &pb.AzureCVMRuntimeData{}
	err := proto.Unmarshal(data, runtimeProto)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(runtimeProto)
}

func (c *AzureCVMConfiguration) MarshalProto() *pb.AzureCVMConfiguration {
	pbConfiguration := &pb.AzureCVMConfiguration{}
	pbConfiguration.SetConsoleEnabled(c.ConsoleEnabled)
	pbConfiguration.SetRootCertThumbprint(c.RootCertThumbprint)
	pbConfiguration.SetSecureBoot(c.SecureBoot)
	pbConfiguration.SetTpmEnabled(c.TpmEnabled)
	pbConfiguration.SetTpmPersisted(c.TpmPersisted)
	pbConfiguration.SetVmUniqueId(c.VmUniqueID)
	return pbConfiguration
}

func (k *AzureCVMKey) MarshalProto() *pb.AzureCVMKey {
	pbKey := &pb.AzureCVMKey{}
	pbKey.SetE(k.E)
	pbKey.SetN(k.N)
	pbKey.SetKty(k.Kty)
	pbKey.SetKid(k.Kid)
	pbKey.SetKeyOps(k.KeyOps)
	return pbKey
}

func (a *AzureCVMRuntimeData) UnmarshalJSON(data []byte) error {
	a.OriginalJSON = data
	a.Signature = sha256.Sum256(data)

	// Define an alias to avoid infinite recursion
	type Alias AzureCVMRuntimeData
	aux := (*Alias)(a)

	return json.Unmarshal(data, aux)
}
