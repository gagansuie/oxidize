use anyhow::Result;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

pub fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    Ok(compress_prepend_size(data))
}

pub fn decompress_data(compressed: &[u8]) -> Result<Vec<u8>> {
    Ok(decompress_size_prepended(compressed)?)
}

pub fn should_compress(data: &[u8], min_size: usize) -> bool {
    if data.len() < min_size {
        return false;
    }

    let sample_size = std::cmp::min(data.len(), 256);
    let sample = &data[..sample_size];

    let mut unique_bytes = [false; 256];
    let mut unique_count = 0;

    for &byte in sample {
        if !unique_bytes[byte as usize] {
            unique_bytes[byte as usize] = true;
            unique_count += 1;
        }
    }

    unique_count < 200
}
