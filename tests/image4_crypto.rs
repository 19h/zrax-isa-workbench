//! Image4 AES trials, NIST SP 800-38A vectors, keybag use and codec probes.

use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
use ctr::cipher::StreamCipher;
use zrax::image4::{self, Mode};
use zrax::{detect_payload, formats::apple, inspection, ClassifierOptions, FileFormat, Isa};

const KEY: [u8; 32] = [0x12; 32];
const IV: [u8; 16] = [0x34; 16];

#[derive(Clone, Copy)]
struct KeybagMaterial {
    key: [u8; 32],
    iv: [u8; 16],
}

fn material(key: [u8; 32], iv: [u8; 16]) -> KeybagMaterial {
    KeybagMaterial { key, iv }
}

fn hex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

/// One DER element: tag, definite length (short or minimal big-endian
/// long-form), contents. Fixtures do not call the Image4 parser.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut data = vec![tag];
    if contents.len() < 128 {
        data.push(u8::try_from(contents.len()).unwrap());
    } else {
        let bytes = contents.len().to_be_bytes();
        let first = bytes.iter().position(|&byte| byte != 0).unwrap();
        data.push(0x80 | u8::try_from(bytes.len() - first).unwrap());
        data.extend_from_slice(&bytes[first..]);
    }
    data.extend_from_slice(contents);
    data
}

fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &items.concat())
}

/// IM4P ::= SEQUENCE { IA5 "IM4P", IA5 "krnl", IA5 description,
/// OCTET payload, optional OCTET keybag }. Keybag holds a DER sequence of
/// { INTEGER class, OCTET IV (16 B), OCTET key (32 B) } records.
fn image(payload: &[u8], keybags: &[KeybagMaterial]) -> Vec<u8> {
    let mut items = vec![
        der(0x16, b"IM4P"),
        der(0x16, b"krnl"),
        der(0x16, b"AES fixture"),
        der(0x04, payload),
    ];
    if !keybags.is_empty() {
        let records: Vec<_> = keybags
            .iter()
            .map(|bag| sequence(&[der(0x02, &[1]), der(0x04, &bag.iv), der(0x04, &bag.key)]))
            .collect();
        items.push(der(0x04, &sequence(&records)));
    }
    sequence(&items)
}

fn encrypt(data: &[u8], mode: Mode) -> Vec<u8> {
    let mut output = data.to_vec();
    match mode {
        Mode::Cbc => {
            let len = output.len();
            cbc::Encryptor::<Aes256>::new((&KEY).into(), (&IV).into())
                .encrypt_padded_mut::<NoPadding>(&mut output, len)
                .unwrap();
        }
        Mode::Ctr => {
            ctr::Ctr128BE::<Aes256>::new((&KEY).into(), (&IV).into()).apply_keystream(&mut output)
        }
    }
    output
}

#[test]
fn nist_sp800_38a_cbc_and_ctr_vectors_cover_all_supported_key_sizes() {
    // NIST SP 800-38A, appendix F.2 and F.5, first plaintext/ciphertext block.
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
    let vectors = [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "7649abac8119b246cee98e9b12e9197d",
            "874d6191b620e3261bef6864990db6ce",
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "4f021db243bc633d7178183a9fa071e8",
            "1abc932417521ca24f2b0459fe7e6e0b",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "601ec313775789a5b7a7f504bbf3d228",
        ),
    ];
    for (key, cbc, ctr) in vectors {
        assert_eq!(
            image4::decrypt(
                &hex(cbc),
                &hex(key),
                &hex("000102030405060708090a0b0c0d0e0f"),
                Mode::Cbc
            )
            .unwrap(),
            plaintext
        );
        assert_eq!(
            image4::decrypt(
                &hex(ctr),
                &hex(key),
                &hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                Mode::Ctr
            )
            .unwrap(),
            plaintext
        );
    }
}

#[test]
fn usable_keybags_select_cbc_or_ctr_and_expose_decoded_subfiles() {
    let plaintext = include_bytes!("fixtures/apple/kernel.macho");
    for mode in [Mode::Cbc, Mode::Ctr] {
        let data = image(&encrypt(plaintext, mode), &[material(KEY, IV)]);
        let payload = detect_payload(&data, &ClassifierOptions::new()).unwrap();
        assert_eq!(payload.format.format, FileFormat::Im4p);
        assert_eq!(payload.primary.isa, Isa::AArch64);
        assert!(payload
            .notes
            .iter()
            .any(|note| note.message.contains("not authenticated")));
        let info = apple::image4_info(&data).unwrap().unwrap();
        assert_eq!(info.keybags[0].key, hex::encode_upper(KEY));
        assert_eq!(info.keybags[0].iv, hex::encode_upper(IV));
        let files = inspection::subfiles(&data).unwrap();
        assert!(!files[0].opaque);
        assert_eq!(files[0].transform, Some(mode.name()));
        assert_eq!(inspection::extract_subfile(&data, 0).unwrap(), plaintext);
    }
}

#[test]
fn every_keybag_within_the_trial_budget_is_considered() {
    let plaintext = include_bytes!("fixtures/apple/kernel.macho");
    let data = image(
        &encrypt(plaintext, Mode::Ctr),
        &[material([0x99; 32], IV), material(KEY, IV)],
    );
    let payload = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(payload.primary.isa, Isa::AArch64);
    let wrapped = image(&encrypt(plaintext, Mode::Ctr), &[material([0x99; 32], IV)]);
    let files = inspection::subfiles(&wrapped).unwrap();
    assert!(files[0].opaque);
    let mut beyond_budget = vec![material([0x99; 32], IV); 8];
    beyond_budget.push(material(KEY, IV));
    let data = image(&encrypt(plaintext, Mode::Ctr), &beyond_budget);
    assert!(inspection::subfiles(&data).unwrap()[0].opaque);
}

#[test]
fn aes_then_framed_and_headerless_compression_trials_recover_exact_bytes() {
    let plaintext = include_bytes!("fixtures/apple/kernel.macho");
    let streams = [
        (
            "DEFLATE",
            miniz_oxide::deflate::compress_to_vec(plaintext, 6),
        ),
        ("LZ4 block", lz4_flex::block::compress(plaintext)),
        (
            "Brotli",
            include_bytes!("fixtures/apple/kernel.macho.br").to_vec(),
        ),
    ];
    for (codec, compressed) in streams {
        let trial = image4::automatic(&encrypt(&compressed, Mode::Ctr), &KEY, &IV).unwrap();
        assert_eq!(trial.data, plaintext);
        assert_eq!(trial.codec, Some(codec));
        let file = image(&compressed, &[]);
        assert_eq!(inspection::extract_subfile(&file, 0).unwrap(), plaintext);
    }
    let lzfse_im4p = include_bytes!("fixtures/apple/krnl.bvx2.im4p");
    let info = apple::image4_info(lzfse_im4p).unwrap().unwrap();
    let stream = &lzfse_im4p[info.offset..info.offset + info.size];
    let encrypted = image(&encrypt(stream, Mode::Ctr), &[material(KEY, IV)]);
    assert_eq!(
        inspection::extract_subfile(&encrypted, 0).unwrap(),
        plaintext
    );
}

#[test]
fn automatic_codec_trials_cannot_silently_discard_nonpadding_trailers() {
    let plaintext = include_bytes!("fixtures/apple/kernel.macho");
    let mut stream = miniz_oxide::deflate::compress_to_vec(plaintext, 6);
    stream.extend_from_slice(b"appended data");
    let ciphertext = encrypt(&stream, Mode::Ctr);
    assert!(image4::automatic(&ciphertext, &KEY, &IV).is_err());
    let candidate = image4::trial(&ciphertext, &KEY, &IV, Mode::Ctr).unwrap();
    assert_eq!(candidate.data, stream);
    assert!(!candidate.recognized);
}

#[test]
fn unsupported_material_and_unrecognized_automatic_output_are_rejected() {
    for (data, key, iv, mode) in [
        (&[][..], &KEY[..], &IV[..], Mode::Ctr),
        (&[0; 16][..], &[0; 20][..], &IV[..], Mode::Ctr),
        (&[0; 16][..], &KEY[..], &[0; 12][..], Mode::Ctr),
        (&[0; 17][..], &KEY[..], &IV[..], Mode::Cbc),
    ] {
        assert!(image4::decrypt(data, key, iv, mode).is_err());
    }
    let ciphertext = encrypt(&[0x5a; 64], Mode::Cbc);
    assert!(image4::automatic(&ciphertext, &KEY, &IV).is_err());
    let trial = image4::trial(&ciphertext, &KEY, &IV, Mode::Cbc).unwrap();
    assert!(!trial.recognized);
    assert_eq!(trial.data, [0x5a; 64]);
    let plaintext = include_bytes!("fixtures/apple/kernel.macho");
    for end in 0..64 {
        let _ = image4::automatic(&encrypt(&plaintext[..end], Mode::Ctr), &KEY, &IV);
    }
}

#[test]
fn keybag_enumeration_is_bounded_before_material_serialization() {
    let at_limit = image(&[0; 16], &vec![material(KEY, IV); 4096]);
    assert_eq!(
        apple::image4_info(&at_limit)
            .unwrap()
            .unwrap()
            .keybags
            .len(),
        4096
    );
    let data = image(&[0; 16], &vec![material(KEY, IV); 4097]);
    let error = apple::image4_info(&data).unwrap_err().to_string();
    assert!(error.contains("keybag count; limit 4096"));
    assert!(detect_payload(&data, &ClassifierOptions::new()).is_err());
}
