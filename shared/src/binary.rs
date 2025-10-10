use std::ffi::CStr;
use std::fmt;
use once_cell::sync::Lazy;
use regex::Regex;

static MARKER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[^\[]*\[*([^]]+)]*").expect("Invalid regex")
});

pub struct DisplayBinary<'a, T>(pub &'a [T]) where T: AsRef<[u8]>;

#[derive(Debug)]
#[derive(PartialEq)]
pub struct Binary(pub(crate) Vec<Vec<u8>>);

pub trait IntoBinary {
    type Error;
    fn into_binary(self) -> Result<Binary, Self::Error>;
}

impl IntoBinary for &str {
    type Error = &'static str;
    fn into_binary(self) -> Result<Binary, Self::Error> {
        Binary::try_from(self)
    }
}

impl IntoBinary for &CStr {
    type Error = &'static str;
    fn into_binary(self) -> Result<Binary, Self::Error> {
        Binary::try_from(self)
    }
}

impl IntoBinary for String {
    type Error = &'static str;
    fn into_binary(self) -> Result<Binary, Self::Error> {
        Binary::try_from(self)
    }
}

impl IntoBinary for &String {
    type Error = &'static str;
    fn into_binary(self) -> Result<Binary, Self::Error> {
        Binary::try_from(self)
    }
}

impl TryFrom<&str> for Binary {
    type Error = &'static str;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let caps = MARKER_RE
            .captures(s)
            .ok_or("No match found")?;
        let capture = caps.get(1).map(|m| m.as_str()).ok_or("Missing capture group")?;
        let mut tmp = Vec::new();
        for part in capture.split(":") {
            tmp.push(base85::decode(part).map_err(|_| "Base85 decoding failed")?)
        }
        Ok(Binary(tmp))
    }
}

impl TryFrom<String> for Binary {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Binary::try_from(s.as_str())
    }
}

impl TryFrom<&String> for Binary {
    type Error = &'static str;
    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Binary::try_from(s.as_str())
    }
}

impl TryFrom<&CStr> for Binary {
    type Error = &'static str;
    fn try_from(s: &CStr) -> Result<Self, Self::Error> {
        Binary::try_from(s.to_str().map_err(|_| "CStr decoding failed")?)
    }
}



impl<'a, T> fmt::Display for DisplayBinary<'a, T>
where
    T: AsRef<[u8]>,
{    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "[[[")?;
    for (i, part) in self.0.iter().enumerate() {
        write!(f, "{}", base85::encode(part.as_ref()))?;
        if i < self.0.len() - 1 {
            write!(f, ":")?;
        }
    }
    write!(f, "]]]")
}
}

impl fmt::Display for Binary{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", DisplayBinary(&self.0))
    }
}

impl Binary {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}



#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use super::*;

    #[test]
    fn test_challenge2read_challenge() {
        for b1 in 0u8..=255 {
            let buf = [b1];
            let bd = Binary(vec!(buf.to_vec(), ));
            let tmp = bd.to_string();
            let bd2 = tmp.into_binary().unwrap();
            assert_eq!(bd, bd2);
        }

        for b1 in 0u8..=255 {
            for b2 in 0u8..=255 {
                let buf = [b1, b2];
                let bd = Binary(vec!(buf.to_vec(), ));
                let tmp = bd.to_string();
                let c_string = CString::new(tmp).unwrap();
                let bd2 = c_string.as_c_str().into_binary().unwrap();
                assert_eq!(bd, bd2);
            }
        }
    }

    #[test]
    fn test_binary_data_back_forth() {
        let mut tmp = Vec::new();
        for b1 in 0u8..=255 {
            let buf = [b1];
            tmp.push(Vec::from(buf));
        }

        for b1 in 0u8..=255 {
            for b2 in 0u8..=255 {
                let buf = [b1, b2];
                tmp.push(buf.to_vec());
            }
        }
        let binarydata = Binary(tmp);
        let tmp = format!("{}", binarydata);
        let c_string = CString::new(tmp).unwrap();
        let binarydata_back = c_string.as_c_str().into_binary().unwrap();
        assert_eq!(binarydata, binarydata_back);
    }

    #[test]
    fn test_str_into_binary() {
        let tmp = "[[[xZKvQyFi{XI(Zc=V;%jX>A#bUy7AtNf@=uWX=f?0]]]";
        let _binary = tmp.into_binary().unwrap();
    }

    #[test]
    fn test_string_into_binary() {
        let tmp = "[[[xZKvQyFi{XI(Zc=V;%jX>A#bUy7AtNf@=uWX=f?0]]]";
        let _binary = tmp.to_string().into_binary().unwrap();
    }


}