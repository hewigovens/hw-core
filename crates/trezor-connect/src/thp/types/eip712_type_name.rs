pub struct Eip712TypeName<'a>(pub &'a str);

impl<'a> Eip712TypeName<'a> {
    pub fn array(self) -> Option<(&'a str, Option<u32>)> {
        let stripped = self.0.strip_suffix(']')?;
        let start = stripped.rfind('[')?;
        let entry = &stripped[..start];
        let size_str = &stripped[start + 1..];
        if size_str.is_empty() {
            return Some((entry, None));
        }
        let size = size_str.parse::<u32>().ok()?;
        Some((entry, Some(size)))
    }

    pub fn number(self) -> Option<(bool, u32)> {
        let (signed, bits) = match self.0.strip_prefix("uint") {
            Some(bits) => (false, bits),
            None => (true, self.0.strip_prefix("int")?),
        };
        let bits = if bits.is_empty() {
            256
        } else {
            bits.parse::<u32>().ok()?
        };
        Some((signed, bits))
    }

    pub fn bytes(self) -> Option<Option<u32>> {
        let suffix = self.0.strip_prefix("bytes")?;
        if suffix.is_empty() {
            return Some(None);
        }
        Some(Some(suffix.parse::<u32>().ok()?))
    }
}
