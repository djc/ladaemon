use err_derive::Error;
use std::collections::HashSet;

/// Model of a single rule in the valid suffixes list.
struct SuffixRule {
    /// Labels to match, some of which may be `*`.
    pub labels: Vec<String>,
    /// Whether this is an exception rule.
    pub exception: bool,
}

/// Errors produced by `DomainValidator::add_valid_suffix`.
#[derive(Debug, Error)]
pub enum SuffixParseError {
    #[error(display = "invalid international domain name")]
    InvalidIdna(#[error(from)] idna::Errors),
    #[error(display = "domain name cannot contain empty labels")]
    ContainsEmptyLabels,
}

/// Errors produced by `DomainValidator::validate`.
#[derive(Debug, Error)]
pub enum DomainValidationError {
    #[error(display = "invalid international domain name")]
    InvalidIdna(#[error(from)] idna::Errors),
    #[error(display = "domain name is blocked")]
    Blocked,
    #[error(display = "domain name contains empty labels")]
    ContainsEmptyLabels,
    #[error(display = "domain name does not have a valid top-level domain")]
    InvalidTld,
    #[error(display = "domain name does not have a valid suffix")]
    InvalidSuffix,
}

/// Validates domains based on some configuration.
#[derive(Default)]
pub struct DomainValidator {
    /// Exact domains to allow.
    allowed_domains: HashSet<String>,
    /// Whether to treat anything not in the allow-list as blocked.
    pub allowed_domains_only: bool,
    /// Exact domains to block.
    blocked_domains: HashSet<String>,
    /// Allowed TLDs.
    valid_tlds: HashSet<String>,
    /// Rules for validating domain suffixes.
    valid_suffixes: Vec<SuffixRule>,
}

impl DomainValidator {
    /// Add a TLD to the set of allowed TLDs.
    pub fn add_allowed_domain(&mut self, domain: &str) -> Result<(), idna::Errors> {
        let domain = idna::domain_to_ascii(domain)?;
        self.allowed_domains.insert(domain);
        Ok(())
    }

    /// Add a TLD to the set of blocked TLDs.
    pub fn add_blocked_domain(&mut self, domain: &str) -> Result<(), idna::Errors> {
        let domain = idna::domain_to_ascii(domain)?;
        self.blocked_domains.insert(domain);
        Ok(())
    }

    /// Add a TLD to the set of valid TLDs.
    pub fn add_valid_tld(&mut self, tld: &str) -> Result<(), idna::Errors> {
        let tld = idna::domain_to_ascii(tld)?;
        self.valid_tlds.insert(tld);
        Ok(())
    }

    /// Add a domain suffix rule to the list of valid suffixes.
    pub fn add_valid_suffix(&mut self, rule: &str) -> Result<(), SuffixParseError> {
        // Check for an exception rule.
        let exception = rule.starts_with("!");
        let slice = if exception { &rule[1..] } else { &rule[..] };

        // Convert to punycode.
        let rule = idna::domain_to_ascii(slice)?;

        // Split labels, and check that none are empty.
        let labels: Vec<_> = rule.split('.').map(str::to_owned).collect();
        if labels.iter().any(|s| s.is_empty()) {
            return Err(SuffixParseError::ContainsEmptyLabels);
        }

        self.valid_suffixes.push(SuffixRule { labels, exception });
        Ok(())
    }

    /// Validate a domain.
    ///
    /// This function expects a normalized domain name per our email normalization spec. This means
    /// the domain must already be punycode and checked for invalid characters.
    pub fn validate(&self, domain: &str) -> Result<(), DomainValidationError> {
        let domain = idna::domain_to_ascii(domain)?;

        // Strip a trailing dot if present.
        let domain = if domain.ends_with('.') {
            &domain[..(domain.len() - 1)]
        } else {
            &domain[..]
        };

        // Short-circuit for allow/block-lists.
        if self.allowed_domains.contains(domain) {
            return Ok(());
        }
        if self.allowed_domains_only || self.blocked_domains.contains(domain) {
            return Err(DomainValidationError::Blocked);
        }

        // Separate into labels, and don't allow empty labels.
        let domain: Vec<_> = domain.split('.').collect();
        if domain.iter().any(|s| s.is_empty()) {
            return Err(DomainValidationError::ContainsEmptyLabels);
        }

        // Verify agains TLD list and suffix list.
        if !self.valid_tlds.contains(*domain.last().unwrap()) {
            return Err(DomainValidationError::InvalidTld);
        }
        if !self.validate_suffix(&domain) {
            return Err(DomainValidationError::InvalidSuffix);
        }

        Ok(())
    }

    /// Validate a domain against the suffix rules.
    fn validate_suffix(&self, domain: &Vec<&str>) -> bool {
        // Track the longest match. (Never contains an exception rule.)
        let mut matched: Option<&SuffixRule> = None;

        for rule in &self.valid_suffixes {
            // Get the last 'n' labels of the domain, where 'n' is the rule length. We can skip
            // rules if the domain doesn't have enough labels in the first place. We check this
            // using an overflow check, so explicitely enforce unsigned here.
            let num_labels: usize = rule.labels.len();
            let domain = match domain.len().checked_sub(num_labels) {
                Some(skip) => &domain[skip..],
                None => continue,
            };

            // Check that each label matches, or is a wildcard.
            if !rule
                .labels
                .iter()
                .enumerate()
                .all(|(idx, label)| *label == "*" || domain[idx] == *label)
            {
                continue;
            }

            // Immediately allow matches for exception rules.
            // (These match an exact registered domain.)
            if rule.exception {
                return true;
            }

            // Store the longest match.
            matched = match matched.take() {
                Some(other) if other.labels.len() > num_labels => Some(other),
                _ => Some(rule),
            };
        }

        // Need at least one more label below the matched suffix.
        // If no match was found, treat as '*'.
        match matched {
            Some(rule) => domain.len() > rule.labels.len(),
            None => domain.len() > 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DomainValidator;
    use crate::config::StringListFileReader;

    #[test]
    fn test_suffixlist() {
        let mut validator = DomainValidator::default();
        // Use the standard lists for tests.
        for tld in StringListFileReader::open("tlds-alpha-by-domain.txt".as_ref()).unwrap() {
            validator.add_valid_tld(&tld.unwrap()).unwrap();
        }
        for suffix in StringListFileReader::open("public_suffix_list.dat".as_ref()).unwrap() {
            validator.add_valid_suffix(&suffix.unwrap()).unwrap();
        }
        // Include `example` TLD to make the 'Unlisted TLD' tests pass.
        validator.add_valid_tld("example").unwrap();

        let check = |input, ok| {
            let res = validator.validate(input);
            if res.is_ok() != ok {
                panic!("Validation of domain '{}' returned: {:?}", input, res);
            }
        };

        // These tests are based on the test suite for the public suffix list:
        // https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt
        //
        // We enable 'Unlisted TLD' tests, because we add TLD validation.

        // Mixed case.
        check("COM", false);
        check("example.COM", true);
        check("WwW.example.COM", true);
        // Leading dot.
        check(".com", false);
        check(".example", false);
        check(".example.com", false);
        check(".example.example", false);
        // Unlisted TLD.
        check("example", false);
        check("example.example", true);
        check("b.example.example", true);
        check("a.b.example.example", true);
        // Listed, but non-Internet, TLD.
        check("local", false);
        check("example.local", false);
        check("b.example.local", false);
        check("a.b.example.local", false);
        // TLD with only 1 rule.
        check("biz", false);
        check("domain.biz", true);
        check("b.domain.biz", true);
        check("a.b.domain.biz", true);
        // TLD with some 2-level rules.
        check("com", false);
        check("example.com", true);
        check("b.example.com", true);
        check("a.b.example.com", true);
        check("uk.com", false);
        check("example.uk.com", true);
        check("b.example.uk.com", true);
        check("a.b.example.uk.com", true);
        check("test.ac", true);
        // TLD with only 1 (wildcard) rule.
        check("mm", false);
        check("c.mm", false);
        check("b.c.mm", true);
        check("a.b.c.mm", true);
        // More complex TLD.
        check("jp", false);
        check("test.jp", true);
        check("www.test.jp", true);
        check("ac.jp", false);
        check("test.ac.jp", true);
        check("www.test.ac.jp", true);
        check("kyoto.jp", false);
        check("test.kyoto.jp", true);
        check("ide.kyoto.jp", false);
        check("b.ide.kyoto.jp", true);
        check("a.b.ide.kyoto.jp", true);
        check("c.kobe.jp", false);
        check("b.c.kobe.jp", true);
        check("a.b.c.kobe.jp", true);
        check("city.kobe.jp", true);
        check("www.city.kobe.jp", true);
        // TLD with a wildcard rule and exceptions.
        check("ck", false);
        check("test.ck", false);
        check("b.test.ck", true);
        check("a.b.test.ck", true);
        check("www.ck", true);
        check("www.www.ck", true);
        // US K12.
        check("us", false);
        check("test.us", true);
        check("www.test.us", true);
        check("ak.us", false);
        check("test.ak.us", true);
        check("www.test.ak.us", true);
        check("k12.ak.us", false);
        check("test.k12.ak.us", true);
        check("www.test.k12.ak.us", true);
        // IDN labels.
        check("食狮.com.cn", true);
        check("食狮.公司.cn", true);
        check("www.食狮.公司.cn", true);
        check("shishi.公司.cn", true);
        check("公司.cn", false);
        check("食狮.中国", true);
        check("www.食狮.中国", true);
        check("shishi.中国", true);
        check("中国", false);
        // Same as above, but punycoded.
        check("xn--85x722f.com.cn", true);
        check("xn--85x722f.xn--55qx5d.cn", true);
        check("www.xn--85x722f.xn--55qx5d.cn", true);
        check("shishi.xn--55qx5d.cn", true);
        check("xn--55qx5d.cn", false);
        check("xn--85x722f.xn--fiqs8s", true);
        check("www.xn--85x722f.xn--fiqs8s", true);
        check("shishi.xn--fiqs8s", true);
        check("xn--fiqs8s", false);
    }
}
