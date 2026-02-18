use std::env;

/// Replace all `${VAR}` occurrences in `input` with the corresponding
/// environment variable value.  Unset variables are replaced with the
/// empty string and a warning is logged.
pub fn interpolate_env(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                var_name.push(ch);
            }
            match env::var(&var_name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    tracing::warn!(var = %var_name, "unset env var in middleware config, using empty string");
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_vars() {
        assert_eq!(interpolate_env("hello world"), "hello world");
    }

    #[test]
    fn single_var() {
        env::set_var("_TEST_MCP_A", "alpha");
        assert_eq!(interpolate_env("key=${_TEST_MCP_A}"), "key=alpha");
        env::remove_var("_TEST_MCP_A");
    }

    #[test]
    fn multiple_vars() {
        env::set_var("_TEST_MCP_X", "1");
        env::set_var("_TEST_MCP_Y", "2");
        assert_eq!(interpolate_env("${_TEST_MCP_X}+${_TEST_MCP_Y}"), "1+2");
        env::remove_var("_TEST_MCP_X");
        env::remove_var("_TEST_MCP_Y");
    }

    #[test]
    fn unset_var_becomes_empty() {
        assert_eq!(interpolate_env("pre-${_NO_SUCH_VAR}-post"), "pre--post");
    }

    #[test]
    fn dollar_without_brace_kept() {
        assert_eq!(interpolate_env("cost is $5"), "cost is $5");
    }
}
