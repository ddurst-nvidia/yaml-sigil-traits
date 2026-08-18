// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use yaml_sigil_traits::signing::{
    AsyncSigner, AsyncSignerWithRng, OutputForm, SignError, SignInvocationError, SignOutcome,
    SignRequest, SignSuccess, Signer, SignerCapabilities, SignerWithRng, SigningKey,
};
use yaml_sigil_traits::transcription::{
    AbstractArtifact, AsyncTranscriber, ComposeOutcome, ComposeRequest, ComposeSuccess,
    DecomposeOutcome, DecomposeRequest, DecomposeResponse, DecomposeStructuralResult, Transcriber,
    TranscriberCapabilities, TranscriberError, TranscriberInvocationError, TranscriptionForm,
};
use yaml_sigil_traits::verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOutcome,
    PreVerifyResponse, PublicKeys, UnverifiedSignature, Verifier, VerifierCapabilities,
    VerifierOptions, VerifierState, VerifyResult,
};
use yaml_sigil_traits::{
    AlgorithmId, CryptoRngCore, OuterConformance, ProtobufWireDecodeAdvertisement,
    YamlSignatureDocumentDuplicateKeyPolicy, YamlSignatureDocumentUnknownFieldPolicy,
};

const ALGORITHMS: &[AlgorithmId] = &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256];
const OUTPUT_FORMS: &[OutputForm] = &[OutputForm::Yaml, OutputForm::Protobuf];
const TRANSCRIPTION_FORMS: &[TranscriptionForm] =
    &[TranscriptionForm::Yaml, TranscriptionForm::Protobuf];
const OUTER_CONFORMANCE: &[OuterConformance] =
    &[OuterConformance::Strict, OuterConformance::SignatureStrict];
const ARTIFACT_FORMS: &[ArtifactForm] = &[ArtifactForm::Yaml, ArtifactForm::Proto];

fn signer_capabilities() -> SignerCapabilities {
    SignerCapabilities {
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::IgnoredAtParse,
        supported_output_forms: OUTPUT_FORMS,
        supported_algorithms: ALGORITHMS,
        best_effort_yaml_validation: false,
        implementation_name: "probe",
        implementation_version: "0",
    }
}

fn transcriber_capabilities() -> TranscriberCapabilities {
    TranscriberCapabilities {
        supported_forms: TRANSCRIPTION_FORMS,
        supported_outer_conformances: OUTER_CONFORMANCE,
        emits_canonical_yaml_envelope: true,
        implementation_name: "probe",
        implementation_version: "0",
    }
}

fn verifier_capabilities() -> VerifierCapabilities {
    VerifierCapabilities {
        conformance_profile: AdvertisedConformanceProfile::Permissive,
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::IgnoredAtParse,
        yaml_signature_unknown_field_policies: Vec::new(),
        supported_forms: ARTIFACT_FORMS,
        supported_algorithms: ALGORITHMS,
        supports_can_pre_verify: true,
        supports_pre_verify: true,
        implementation_name: "probe",
        implementation_version: "0",
    }
}

struct ProbeSigner;

impl Signer for ProbeSigner {
    type Ed25519SigningKey = ();
    type P256SigningKey = ();

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    fn sign(&self, _req: &SignRequest<'_, (), ()>) -> SignOutcome {
        SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm)
    }
}

impl SignerWithRng for ProbeSigner {
    fn capabilities_with_rng(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    fn sign_with_rng(
        &self,
        req: &SignRequest<'_, (), ()>,
        _rng: &mut dyn CryptoRngCore,
    ) -> SignOutcome {
        Signer::sign(self, req)
    }
}

impl AsyncSigner for ProbeSigner {
    type Ed25519SigningKey = ();
    type P256SigningKey = ();

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    async fn sign(&self, _req: &SignRequest<'_, (), ()>) -> SignOutcome {
        SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm)
    }
}

impl AsyncSignerWithRng for ProbeSigner {
    fn capabilities_with_rng(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    async fn sign_with_rng(
        &self,
        req: &SignRequest<'_, (), ()>,
        _rng: &mut (dyn CryptoRngCore + Send),
    ) -> SignOutcome {
        AsyncSigner::sign(self, req).await
    }
}

struct ProbeTranscriber;

impl Transcriber for ProbeTranscriber {
    fn capabilities(&self) -> TranscriberCapabilities {
        transcriber_capabilities()
    }

    fn compose(&self, _req: &ComposeRequest<'_>) -> ComposeOutcome {
        ComposeOutcome::Invocation(TranscriberInvocationError::InvalidOrUnsupportedForm)
    }

    fn decompose(&self, _req: &DecomposeRequest<'_>) -> DecomposeResponse {
        DecomposeResponse::Invocation(TranscriberInvocationError::InvalidOrUnsupportedForm)
    }
}

impl AsyncTranscriber for ProbeTranscriber {
    fn capabilities(&self) -> TranscriberCapabilities {
        transcriber_capabilities()
    }

    async fn compose(&self, req: &ComposeRequest<'_>) -> ComposeOutcome {
        Transcriber::compose(self, req)
    }

    async fn decompose(&self, req: &DecomposeRequest<'_>) -> DecomposeResponse {
        Transcriber::decompose(self, req)
    }
}

struct ProbeVerifier;

impl Verifier for ProbeVerifier {
    type Ed25519VerifyingKey = ();
    type P256VerifyingKey = ();

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }

    fn pre_verify(
        &self,
        _input_bytes: &[u8],
        form: ArtifactForm,
        _allow_unsigned: bool,
        _include_parser_observations: bool,
    ) -> PreVerifyResponse {
        PreVerifyResponse {
            outcome: PreVerifyOutcome::Unsigned,
            form,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        }
    }

    fn verify(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, (), ()>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Ok(VerifierState::Unsigned)
    }

    fn verify_with_metadata(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, (), ()>,
        _options: VerifierOptions,
        _include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        Ok(VerifyResult {
            state: VerifierState::Unsigned,
            parser_observations: Vec::new(),
        })
    }

    fn verify_from_pre_verify(
        &self,
        _pre: &PreVerifyResponse,
        _keys: &PublicKeys<'_, (), ()>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Ok(VerifierState::Unsigned)
    }
}

impl AsyncVerifier for ProbeVerifier {
    type Ed25519VerifyingKey = ();
    type P256VerifyingKey = ();

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }

    async fn pre_verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> PreVerifyResponse {
        Verifier::pre_verify(
            self,
            input_bytes,
            form,
            allow_unsigned,
            include_parser_observations,
        )
    }

    async fn verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_, (), ()>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Verifier::verify(self, input_bytes, form, keys, options)
    }

    async fn verify_with_metadata(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_, (), ()>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        Verifier::verify_with_metadata(
            self,
            input_bytes,
            form,
            keys,
            options,
            include_parser_observations,
        )
    }

    async fn verify_from_pre_verify(
        &self,
        pre: &PreVerifyResponse,
        keys: &PublicKeys<'_, (), ()>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Verifier::verify_from_pre_verify(self, pre, keys, options)
    }
}

fn assert_send<T: Send>(_value: T) {}

fn assert_async_bounds<'a>(
    signer: &'a ProbeSigner,
    sign_request: &'a SignRequest<'_, (), ()>,
    rng: &'a mut (dyn CryptoRngCore + Send),
    transcriber: &'a ProbeTranscriber,
    compose_request: &'a ComposeRequest<'_>,
    verifier: &'a ProbeVerifier,
    keys: &'a PublicKeys<'_, (), ()>,
) {
    assert_send(AsyncSigner::sign(signer, sign_request));
    assert_send(AsyncSignerWithRng::sign_with_rng(signer, sign_request, rng));
    assert_send(AsyncTranscriber::compose(transcriber, compose_request));
    assert_send(AsyncVerifier::verify(
        verifier,
        &[],
        ArtifactForm::Yaml,
        keys,
        VerifierOptions::default(),
    ));
}

fn assert_signer_object_safe(
    _signer: &dyn SignerWithRng<Ed25519SigningKey = (), P256SigningKey = ()>,
) {
}

fn exercise_dtos(key: SigningKey<'_, (), ()>) {
    let _request = SignRequest {
        payload: &[],
        algorithm: AlgorithmId::Ed25519,
        key,
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    let _ = SignError::YamlSerialize(String::new());
    let _ = SignOutcome::Success(SignSuccess {
        artifact: Vec::new(),
        modified_payload: Vec::new(),
    });

    let _ = AbstractArtifact {
        payload: Vec::new(),
        signature_carrier: Vec::new(),
    };
    let _ = ComposeOutcome::Success(ComposeSuccess {
        artifact: Vec::new(),
        form: TranscriptionForm::Yaml,
    });
    let _ = ComposeOutcome::Error(TranscriberError::InvalidPayloadBytes);
    let _ = DecomposeResponse::Structural(DecomposeStructuralResult {
        outcome: DecomposeOutcome::Ok,
        payload: None,
        signature_carrier: None,
        detail: None,
    });

    let _ = InvocationError::InvalidAlgorithmParameters;
    let _ = VerifierState::Verified {
        payload: Vec::new(),
        algorithm: AlgorithmId::Ed25519,
    };
    let _ = UnverifiedSignature {
        algorithm: AlgorithmId::Ed25519,
        keyid: None,
        signature_octets: Vec::new(),
    };
    let _ = PreVerifyResponse {
        outcome: PreVerifyOutcome::MetadataParseFailure,
        form: ArtifactForm::Proto,
        unverified_payload_bytes: None,
        unverified_signature: None,
        parser_observations: Vec::new(),
    };
    let _: PublicKeys<'_, (), ()> = PublicKeys {
        ed25519: None,
        p256: None,
    };
}
