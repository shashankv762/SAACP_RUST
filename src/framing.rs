use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// Magic bytes
pub const MEASC_MAGIC: &[u8; 4] = b"SACP";
pub const MEASC_HEADER_SIZE: usize = 128;
pub const MAX_PAYLOAD_SIZE: usize = 10_000_000; // 10 MB MTU

// Flag constants
pub const FLAG_COVER_TRAFFIC: u8 = 0x80;
pub const FLAG_EXTERNAL_INPUT: u8 = 0x80; // Alias for FLAG_COVER_TRAFFIC - forces FULL gate tier
pub const FLAG_HAS_TOKEN: u8 = 0x01;
pub const FLAG_BINARY_STREAM: u8 = 0x02;
pub const FLAG_ENCRYPTED: u8 = 0x10;

// Action class constants
pub const ACTION_CLASS_READ_ONLY: u8 = 0x00;
pub const ACTION_CLASS_REVERSIBLE: u8 = 0x01;
pub const ACTION_CLASS_IRREVERSIBLE: u8 = 0x02;

/// MEASC 128-byte frame header.
#[derive(Debug, Clone)]
pub struct MEASCFrame {
    pub schema_id: u16,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub payload_length: u32,
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub psn: u64,
    pub context_ref_id: [u8; 32],
    pub context_version: u32,
    pub w3c_traceparent: [u8; 24],
}

impl MEASCFrame {
    /// Default constructor with all fields zeroed.
    pub fn new() -> Self {
        Self {
            schema_id: 0,
            status_code: 0,
            flags: 0,
            action_class: 0,
            payload_length: 0,
            session_id: [0u8; 16],
            epoch_id: 0,
            psn: 0,
            context_ref_id: [0u8; 32],
            context_version: 0,
            w3c_traceparent: [0u8; 24],
        }
    }

    /// Serialize to exactly 128 bytes (big-endian).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; MEASC_HEADER_SIZE];

        // Offset 0: magic (4 bytes)
        buf[0..4].copy_from_slice(MEASC_MAGIC);

        // Offset 4: schema_id (2 bytes, big-endian)
        buf[4..6].copy_from_slice(&self.schema_id.to_be_bytes());

        // Offset 6: status_code (1 byte)
        buf[6] = self.status_code;

        // Offset 7: flags (1 byte)
        buf[7] = self.flags;

        // Offset 8: action_class (1 byte)
        buf[8] = self.action_class;

        // Offset 9: padding1 (3 bytes) - already zeros

        // Offset 12: payload_length (4 bytes, big-endian)
        buf[12..16].copy_from_slice(&self.payload_length.to_be_bytes());

        // Offset 16: session_id (16 bytes)
        buf[16..32].copy_from_slice(&self.session_id);

        // Offset 32: epoch_id (4 bytes, big-endian)
        buf[32..36].copy_from_slice(&self.epoch_id.to_be_bytes());

        // Offset 36: psn (8 bytes, big-endian)
        buf[36..44].copy_from_slice(&self.psn.to_be_bytes());

        // Offset 44: context_ref_id (32 bytes)
        buf[44..76].copy_from_slice(&self.context_ref_id);

        // Offset 76: context_version (4 bytes, big-endian)
        buf[76..80].copy_from_slice(&self.context_version.to_be_bytes());

        // Offset 80: w3c_traceparent (24 bytes)
        buf[80..104].copy_from_slice(&self.w3c_traceparent);

        // Offset 104: reserved (4 bytes) - already zeros
        // Offset 108: padding2 (20 bytes) - already zeros

        buf
    }

    /// Deserialize from 128 bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SAACPHardDrop> {
        if data.len() < MEASC_HEADER_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "Frame too short: expected {} bytes, got {}",
                    MEASC_HEADER_SIZE,
                    data.len()
                ),
            ));
        }

        // Verify magic
        if &data[0..4] != MEASC_MAGIC {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "Invalid magic bytes: expected {:?}, got {:?}",
                    MEASC_MAGIC,
                    &data[0..4]
                ),
            ));
        }

        let schema_id = u16::from_be_bytes([data[4], data[5]]);
        let status_code = data[6];
        let flags = data[7];
        let action_class = data[8];
        // Skip padding1 at offset 9..12

        let payload_length = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[16..32]);

        let epoch_id = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);

        let psn = u64::from_be_bytes([
            data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
        ]);

        let mut context_ref_id = [0u8; 32];
        context_ref_id.copy_from_slice(&data[44..76]);

        let context_version = u32::from_be_bytes([data[76], data[77], data[78], data[79]]);

        let mut w3c_traceparent = [0u8; 24];
        w3c_traceparent.copy_from_slice(&data[80..104]);

        Ok(Self {
            schema_id,
            status_code,
            flags,
            action_class,
            payload_length,
            session_id,
            epoch_id,
            psn,
            context_ref_id,
            context_version,
            w3c_traceparent,
        })
    }
}

/// Parsed packet with decrypted payload.
#[derive(Debug, Clone)]
pub struct ParsedFrame {
    pub schema_id: u8,
    pub status_code: u8,
    pub flags: u8,
    pub action_class: u8,
    pub session_uuid: String,
    pub sequence_id: u64,
    pub context_state_id: String,
    pub context_version: u64,
    pub traceparent: Vec<u8>,
    pub payload: Vec<u8>,
}

impl MEASCFrame {
    /// Parse a raw packet: decode header, verify magic, extract payload.
    /// In a full implementation this would also AES-GCM decrypt the payload.
    /// For now, it extracts the payload from after the header.
    pub fn parse_header(packet: &[u8], _secret_key: &[u8]) -> Result<ParsedFrame, SAACPHardDrop> {
        let frame = Self::decode(packet)?;
        let payload_start = MEASC_HEADER_SIZE;
        let payload_end = payload_start + frame.payload_length as usize;
        if packet.len() < payload_end {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "Packet too short for declared payload: need {} bytes, got {}",
                    payload_end, packet.len()
                ),
            ));
        }
        let payload = packet[payload_start..payload_end].to_vec();
        let session_uuid = hex::encode(frame.session_id);
        let context_state_id = hex::encode(frame.context_ref_id);
        let traceparent = frame.w3c_traceparent.to_vec();

        Ok(ParsedFrame {
            schema_id: frame.schema_id as u8,
            status_code: frame.status_code,
            flags: frame.flags,
            action_class: frame.action_class,
            session_uuid,
            sequence_id: frame.psn,
            context_state_id,
            context_version: frame.context_version as u64,
            traceparent,
            payload,
        })
    }
}

/// RGC Gate 1 pre-decryption payload size check.
pub fn check_payload_size(size: usize) -> Result<(), SAACPHardDrop> {
    if size > MAX_PAYLOAD_SIZE {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::PayloadTooLarge,
            format!(
                "Payload size {} exceeds maximum {}",
                size, MAX_PAYLOAD_SIZE
            ),
        ));
    }
    Ok(())
}
