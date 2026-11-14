use misb::{au_cells, AuCell};
use std::io::{self, Read};

pub fn read_cell<'a>(input: &mut dyn Read, buf: &'a mut Vec<u8>) -> io::Result<Option<AuCell<'a>>> {
    buf.clear();
    input.take(5).read_to_end(buf)?;
    if buf.len() == 5 {
        let len = u16::from_be_bytes([buf[3], buf[4]]);
        input.take(u64::from(len)).read_to_end(buf)?;
    }
    au_cells(buf).next().transpose().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
