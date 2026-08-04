//! The naming template a provider renders SecretSpec's naming convention
//! through.
//!
//! Every provider has to answer the same question — how does
//! `(project, profile, key)` become a name in this store? — and several answer
//! it with a user-supplied format string. This module owns that format string
//! for all of them: one parser, one renderer, one default, so a provider
//! declares its template and inherits the rest from
//! [`Provider::convention_address`](super::Provider::convention_address).

use std::fmt;
use std::sync::LazyLock;

/// The naming convention rendered when a provider is given no template:
/// `secretspec/{project}/{profile}/{key}`.
pub const CONVENTION: &str = "secretspec/{project}/{profile}/{key}";

static CONVENTION_TEMPLATE: LazyLock<NameTemplate> =
    LazyLock::new(|| NameTemplate::new(CONVENTION));

/// One piece of a parsed template: literal text, or a value to substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Project,
    Profile,
    Key,
}

/// A parsed naming template.
///
/// Parsed once, when a provider is configured, rather than on every address:
/// rendering walks segments instead of rewriting the string three times.
///
/// # Placeholders
///
/// `{project}`, `{profile}` and `{key}` are substituted. Any other braced word
/// is kept as literal text — the store may legitimately want a brace in a name,
/// and a provider that wants to reject unknown placeholders can do so when it
/// parses its URI, where it can report the mistake against the URI the user
/// actually wrote.
///
/// # Example
///
/// ```ignore
/// let template = NameTemplate::new("team/{profile}/{key}");
/// assert_eq!(template.render("myapp", "production", "DATABASE_URL"), "team/production/DATABASE_URL");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameTemplate {
    /// The template as written, kept verbatim so `uri()` round-trips it.
    source: String,
    segments: Vec<Segment>,
}

impl NameTemplate {
    /// Parses a template. Never fails: unrecognized placeholders are literal
    /// text, which is what the string-rewriting implementations this replaces
    /// did with them.
    pub fn new(source: impl Into<String>) -> Self {
        let source = source.into();
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut rest = source.as_str();

        while let Some(open) = rest.find('{') {
            let (before, from_open) = rest.split_at(open);
            literal.push_str(before);

            // An unclosed `{` is literal to the end of the template.
            let Some(close) = from_open.find('}') else {
                literal.push_str(from_open);
                rest = "";
                break;
            };

            let placeholder = match &from_open[1..close] {
                "project" => Some(Segment::Project),
                "profile" => Some(Segment::Profile),
                "key" => Some(Segment::Key),
                _ => None,
            };

            match placeholder {
                Some(segment) => {
                    if !literal.is_empty() {
                        segments.push(Segment::Literal(std::mem::take(&mut literal)));
                    }
                    segments.push(segment);
                }
                None => literal.push_str(&from_open[..=close]),
            }

            rest = &from_open[close + 1..];
        }

        literal.push_str(rest);
        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }

        Self { source, segments }
    }

    /// The template used when a provider is configured with none.
    pub fn convention() -> &'static NameTemplate {
        &CONVENTION_TEMPLATE
    }

    /// Substitutes the convention's three values.
    ///
    /// One pass over the parsed segments, so a value that happens to contain a
    /// placeholder — a project literally named `{key}` — is substituted in, not
    /// substituted through.
    pub fn render(&self, project: &str, profile: &str, key: &str) -> String {
        let mut rendered = String::with_capacity(self.source.len() + project.len() + key.len());
        for segment in &self.segments {
            rendered.push_str(match segment {
                Segment::Literal(text) => text,
                Segment::Project => project,
                Segment::Profile => profile,
                Segment::Key => key,
            });
        }
        rendered
    }

    /// The template as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether this is the default convention, which a provider's `uri()` omits
    /// rather than spelling out.
    pub fn is_convention(&self) -> bool {
        self.source == CONVENTION
    }

    /// Whether the rendered name varies with the project.
    pub fn references_project(&self) -> bool {
        self.segments.contains(&Segment::Project)
    }

    /// Whether the rendered name varies with the profile.
    pub fn references_profile(&self) -> bool {
        self.segments.contains(&Segment::Profile)
    }

    /// Whether the rendered name varies with the key.
    ///
    /// A template that does not is a collision in every store: every secret in
    /// the profile renders to one name.
    pub fn references_key(&self) -> bool {
        self.segments.contains(&Segment::Key)
    }

    /// Whether the rendered name distinguishes one project or profile from
    /// another.
    ///
    /// A template that does not is safe where the URI names a per-project
    /// container — a KDBX file, a vault — and a collision where it does not.
    /// A provider that cannot resolve such a collision safely refuses the
    /// template in [`convention_address`](super::Provider::convention_address);
    /// see [`OnePasswordProvider`](super::onepassword::OnePasswordProvider) for
    /// the worked case.
    pub fn scopes_by_project_or_profile(&self) -> bool {
        self.references_project() || self.references_profile()
    }
}

impl Default for NameTemplate {
    fn default() -> Self {
        Self::convention().clone()
    }
}

impl fmt::Display for NameTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl From<&str> for NameTemplate {
    fn from(source: &str) -> Self {
        Self::new(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convention_renders_the_default_layout() {
        assert_eq!(
            NameTemplate::convention().render("myapp", "production", "DATABASE_URL"),
            "secretspec/myapp/production/DATABASE_URL"
        );
    }

    #[test]
    fn default_is_the_convention() {
        assert_eq!(NameTemplate::default(), *NameTemplate::convention());
        assert!(NameTemplate::default().is_convention());
        assert!(!NameTemplate::new("{key}").is_convention());
    }

    #[test]
    fn renders_a_custom_template() {
        let template = NameTemplate::new("team/{profile}/{key}");
        assert_eq!(
            template.render("myapp", "production", "DATABASE_URL"),
            "team/production/DATABASE_URL"
        );
    }

    #[test]
    fn renders_a_flat_template() {
        assert_eq!(
            NameTemplate::new("{key}").render("myapp", "production", "DATABASE_URL"),
            "DATABASE_URL"
        );
    }

    #[test]
    fn placeholders_may_repeat_and_reorder() {
        assert_eq!(
            NameTemplate::new("{key}/{project}/{key}").render("myapp", "production", "TOKEN"),
            "TOKEN/myapp/TOKEN"
        );
    }

    #[test]
    fn unknown_placeholders_are_literal_text() {
        // `{prof}` is a typo for `{profile}`; the string-rewriting
        // implementations this replaces left it in the rendered name, and so
        // does this, until URI parsing learns to reject it.
        assert_eq!(
            NameTemplate::new("{prof}/{key}").render("myapp", "production", "TOKEN"),
            "{prof}/TOKEN"
        );
    }

    #[test]
    fn unclosed_brace_is_literal_text() {
        assert_eq!(
            NameTemplate::new("weird{/{key}").render("myapp", "production", "TOKEN"),
            "weird{/{key}"
        );
    }

    #[test]
    fn values_containing_placeholders_are_not_re_substituted() {
        // The `.replace()` chains this replaces ran left to right, so a project
        // named `{key}` had the *key* substituted into it by the third call.
        assert_eq!(
            NameTemplate::new("{project}/{key}").render("{key}", "production", "TOKEN"),
            "{key}/TOKEN"
        );
    }

    #[test]
    fn source_round_trips() {
        let source = "vault/{profile}/{key}";
        assert_eq!(NameTemplate::new(source).as_str(), source);
        assert_eq!(NameTemplate::new(source).to_string(), source);
    }

    #[test]
    fn reports_which_values_it_references() {
        let convention = NameTemplate::convention();
        assert!(convention.references_project());
        assert!(convention.references_profile());
        assert!(convention.references_key());
        assert!(convention.scopes_by_project_or_profile());

        let flat = NameTemplate::new("{key}");
        assert!(!flat.references_project());
        assert!(!flat.references_profile());
        assert!(flat.references_key());
        assert!(!flat.scopes_by_project_or_profile());
    }

    #[test]
    fn either_of_project_or_profile_scopes_the_name() {
        assert!(NameTemplate::new("{project}/{key}").scopes_by_project_or_profile());
        assert!(NameTemplate::new("{profile}/{key}").scopes_by_project_or_profile());
    }

    #[test]
    fn a_literal_placeholder_name_is_not_a_reference() {
        // `{prof}` is literal text, so it neither renders the profile nor
        // scopes the name by it.
        let template = NameTemplate::new("{prof}/{key}");
        assert!(!template.references_profile());
        assert!(!template.scopes_by_project_or_profile());
    }

    #[test]
    fn empty_template_renders_empty() {
        assert_eq!(
            NameTemplate::new("").render("myapp", "production", "TOKEN"),
            ""
        );
    }
}
