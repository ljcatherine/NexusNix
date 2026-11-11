//! POSIX shell quoting. Every dynamic word sent to a remote shell goes through
//! [`quote`]; nothing is ever concatenated unquoted.

/// Quote `s` as a single POSIX shell word using single quotes.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Join words, quoting each.
pub fn join(words: &[&str]) -> String {
    words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_metacharacters() {
        assert_eq!(quote("a'b"), "'a'\\''b'");
        assert_eq!(quote("$(rm -rf /);`x`"), "'$(rm -rf /);`x`'");
        assert_eq!(join(&["ls", "-la", "x y"]), "'ls' '-la' 'x y'");
    }
}
