//! Opening stored and transformed container members in their own coordinates.

use zrax::inspection::{extract_subfile, subfiles};

#[test]
fn compressed_im4p_member_returns_decoded_bytes_instead_of_parent_ranges() {
    let data = include_bytes!("fixtures/apple/krnl.bvx2.im4p");
    let files = subfiles(data).unwrap();
    let kernel = files.iter().find(|file| file.label == "krnl").unwrap();
    assert_eq!(kernel.transform, Some("LZFSE"));
    assert_ne!(kernel.stored_size, kernel.size);
    assert_eq!(
        extract_subfile(data, kernel.index).unwrap(),
        include_bytes!("fixtures/apple/kernel.macho")
    );
    assert!(extract_subfile(data, usize::MAX).is_err());
    assert!(extract_subfile(data, files.len()).is_err());
}

#[test]
fn ordinary_binaries_have_no_subfiles() {
    let data = include_bytes!("fixtures/apple/kernel.macho");
    assert!(subfiles(data).unwrap().is_empty());
    assert!(extract_subfile(data, 0).is_err());
}

#[test]
fn archive_browsing_includes_data_and_opaque_encrypted_members() {
    let data = include_bytes!("fixtures/archives/stored.zip");
    let listed = subfiles(data).unwrap();
    assert!(listed.iter().any(|file| file.label.ends_with(".elf")));
    let notes = listed
        .iter()
        .find(|file| file.label == "notes.txt")
        .unwrap();
    assert_eq!(
        extract_subfile(data, notes.index).unwrap(),
        b"Synthetic archive member; not a recognized format.\n"
    );
    let classified =
        zrax::formats::archives::parse_container(data, zrax::formats::archives::Layout::Zip)
            .unwrap();
    assert!(!classified
        .children
        .iter()
        .any(|child| child.label == "notes.txt"));
    let encrypted = include_bytes!("fixtures/archives/encrypted.zip");
    let listed = subfiles(encrypted).unwrap();
    assert!(!listed.is_empty());
    assert!(listed.iter().all(|file| file.opaque));
    for file in listed {
        let bytes = extract_subfile(encrypted, file.index).unwrap();
        assert_eq!(bytes.len(), file.stored_size);
        assert_eq!(
            bytes,
            encrypted[file.offset..file.offset + file.stored_size]
        );
    }
}

#[test]
fn ar_members_keep_names_and_use_exact_bytes_after_the_member_header() {
    let payload = include_bytes!("fixtures/apple/kernel.macho");
    let mut data = b"!<arch>\n".to_vec();
    // SysV ar's 60-byte ASCII header: name, date, UID, GID, mode, size,
    // and the two-byte terminator. Payload follows at byte offset 68.
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        "kernel.o/",
        0,
        0,
        0,
        "100644",
        payload.len()
    );
    assert_eq!(header.len(), 60);
    data.extend_from_slice(header.as_bytes());
    data.extend_from_slice(payload);
    let files = subfiles(&data).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].label, "kernel.o");
    assert_eq!(files[0].offset, 68);
    assert_eq!(extract_subfile(&data, 0).unwrap(), payload);
}
