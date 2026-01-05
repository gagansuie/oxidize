use oxidize_common::{compress_data, decompress_data, should_compress};

#[test]
fn test_compression_roundtrip() {
    let original = b"Hello, World! This is a test message that should compress well.".repeat(10);

    let compressed = compress_data(&original).expect("Compression failed");
    let decompressed = decompress_data(&compressed).expect("Decompression failed");

    assert_eq!(original.to_vec(), decompressed);
    assert!(
        compressed.len() < original.len(),
        "Data should be smaller after compression"
    );
}

#[test]
fn test_compression_ratio() {
    let repetitive_data = vec![0x42; 1000];
    let compressed = compress_data(&repetitive_data).unwrap();

    let ratio = compressed.len() as f64 / repetitive_data.len() as f64;
    assert!(
        ratio < 0.1,
        "Repetitive data should compress to <10% of original size"
    );
}

#[test]
fn test_random_data_compression() {
    let random_data: Vec<u8> = (0..1000).map(|i| (i * 73 + 19) as u8).collect();
    let compressed = compress_data(&random_data).unwrap();
    let decompressed = decompress_data(&compressed).unwrap();

    assert_eq!(random_data, decompressed);
}

#[test]
fn test_should_compress_small_data() {
    let small_data = vec![1, 2, 3, 4, 5];
    assert!(
        !should_compress(&small_data, 100),
        "Small data should not be compressed"
    );
}

#[test]
fn test_should_compress_large_repetitive() {
    let repetitive = vec![0xAA; 1000];
    assert!(
        should_compress(&repetitive, 100),
        "Large repetitive data should be compressed"
    );
}

#[test]
fn test_should_compress_high_entropy() {
    let high_entropy: Vec<u8> = (0..1000).map(|i| i as u8).collect();
    assert!(
        !should_compress(&high_entropy, 100),
        "High entropy data should not be compressed"
    );
}

#[test]
fn test_empty_data_compression() {
    let empty: Vec<u8> = vec![];
    let compressed = compress_data(&empty).unwrap();
    let decompressed = decompress_data(&compressed).unwrap();
    assert_eq!(empty, decompressed);
}
