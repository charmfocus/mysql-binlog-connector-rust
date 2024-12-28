use crate::binlog_error::BinlogError;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::io::Cursor;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GtidEvent {
    pub flags: u8,
    pub gtid: String,
}

impl GtidEvent {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<Self, BinlogError> {
        // refer: https://dev.mysql.com/doc/refman/8.0/en/replication-gtids-concepts.html
        // refer: https://dev.mysql.com/doc/dev/mysql-server/latest/classbinary__log_1_1Gtid__event.html
        let flags = cursor.read_u8()?;
        let sid = Self::read_uuid(cursor)?;
        let gno = cursor.read_u64::<LittleEndian>()?;

        Ok(GtidEvent {
            flags,
            gtid: format!("{}:{}", sid, gno),
        })
    }

    pub fn read_uuid(cursor: &mut Cursor<&Vec<u8>>) -> Result<String, BinlogError> {
        Ok(format!(
            "{}-{}-{}-{}-{}",
            Self::bytes_to_hex_string(cursor, 4)?,
            Self::bytes_to_hex_string(cursor, 2)?,
            Self::bytes_to_hex_string(cursor, 2)?,
            Self::bytes_to_hex_string(cursor, 2)?,
            Self::bytes_to_hex_string(cursor, 6)?,
        ))
    }

    fn bytes_to_hex_string(
        cursor: &mut Cursor<&Vec<u8>>,
        byte_count: u8,
    ) -> Result<String, BinlogError> {
        let mut res = String::new();
        for _ in 0..byte_count {
            write!(&mut res, "{:02x}", cursor.read_u8()?)?;
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gtid_event() {
        // 构造一个 GTID 事件的二进制数据
        // flags(1) + uuid(16) + gno(8)
        let data = vec![
            0x01, // flags
            // UUID: 87fe8228-c034-11eb-aca2-0242ac1a0002
            0x87, 0xfe, 0x82, 0x28, // time_low
            0xc0, 0x34, // time_mid
            0x11, 0xeb, // time_hi_and_version
            0xac, 0xa2, // clock_seq
            0x02, 0x42, 0xac, 0x1a, 0x00, 0x02, // node
            // GNO: 1
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut cursor = Cursor::new(&data);
        let gtid = GtidEvent::parse(&mut cursor).unwrap();
        assert_eq!(gtid.flags, 1);
        assert_eq!(gtid.gtid, "87fe8228-c034-11eb-aca2-0242ac1a0002:1");

        // let begin_gtid_str = "87fe8228-c034-11eb-aca2-0242ac1a0002:1-1";
        // let mut gtid_set = GtidSet::new(&begin_gtid_str).unwrap();

        // // 添加一个 GTID
        // let last_gtid_str = "87fe8228-c034-11eb-aca2-0242ac1a0002:5";
        // gtid_set.add(last_gtid_str).unwrap();
        // println!("{:?}", gtid_set.to_string());
    }
}
