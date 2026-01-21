use crate::error::Error;

pub fn env_var(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| {
        Error::Configuration(format!(
            "{} environment variable is missing. Set it in .env or .env.example",
            key
        ))
    })
}

pub fn env_var_parse<T: std::str::FromStr>(key: &str, expected_format: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Debug,
{
    let value = env_var(key)?;
    value.parse().map_err(|e| {
        Error::Configuration(format!(
            "Invalid {} format: {:?}. Expected format: {}",
            key, e, expected_format
        ))
    })
}
