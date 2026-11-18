//! Bounds on a Handlebars template before and while it is rendered.
//!
//! The template is the submitted source itself, so its STRUCTURE is
//! caller-controlled, not only the config values substituted into it. Three
//! shapes turn a few hundred bytes into a dead controller:
//!
//! * **Partials.** An inline partial that includes itself recurses until the
//!   stack overflows (handlebars' self-include guard compares template names,
//!   and an inline partial has none); one that includes its predecessor twice
//!   doubles the output per level. No module template needs a partial, so the
//!   whole family — partials, partial blocks, inline partials and decorators —
//!   is refused.
//! * **Deep nesting.** The parser and the renderer both recurse per nested
//!   block and per nested subexpression; ten thousand `{{#if}}` overflow the
//!   stack inside `Template::compile`. Depth is therefore bounded on the raw
//!   text, BEFORE the template is parsed.
//! * **Iteration.** `{{#each}}` over a config collection repeats its body, and
//!   nested `each` multiplies. The work a render can do is bounded statically
//!   from the template tree and the largest collection in the config, and the
//!   bytes it can write are bounded by [`CappedWriter`].

use anyhow::{bail, Result};
use handlebars::template::{Parameter, Template, TemplateElement};

/// Deepest nesting of `{{#block}}` tags, and of `(sub (expressions))` inside
/// one tag. Both the parser and the renderer recurse once per level; real
/// module templates nest a handful of levels at most.
pub(crate) const MAX_NESTING_DEPTH: usize = 16;

/// Upper bound on element evaluations one render may perform (see
/// [`render_work`]).
pub(crate) const MAX_RENDER_WORK: u64 = 1_000_000;

/// Rendered output may be this many times the source-size cap.
pub(crate) const RENDERED_OUTPUT_FACTOR: usize = 4;

/// Refuse a template whose block or subexpression nesting passes
/// [`MAX_NESTING_DEPTH`].
///
/// A scan of the raw text, because it must run before the parser does. It
/// over-counts on purpose — a `(` inside a string literal in a tag, or tag-like
/// text inside a raw block, counts — since refusing an unusual template is the
/// safe direction and a missed level is not.
pub(crate) fn check_nesting(template: &str) -> Result<()> {
    let bytes = template.as_bytes();
    let mut blocks: usize = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'{' || bytes[i + 1] != b'{' {
            i += 1;
            continue;
        }
        i += 2;
        while i < bytes.len() && (bytes[i] == b'{' || bytes[i] == b'~') {
            i += 1;
        }
        match bytes.get(i) {
            Some(b'#') => {
                blocks += 1;
                if blocks > MAX_NESTING_DEPTH {
                    bail!(
                        "template-too-deep: block helpers are nested more than \
                         {MAX_NESTING_DEPTH} levels deep"
                    );
                }
            }
            Some(b'/') => blocks = blocks.saturating_sub(1),
            _ => {}
        }
        let mut parens: usize = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'}' if bytes.get(i + 1) == Some(&b'}') => break,
                b'(' => {
                    parens += 1;
                    if parens > MAX_NESTING_DEPTH {
                        bail!(
                            "template-too-deep: subexpressions are nested more than \
                             {MAX_NESTING_DEPTH} levels deep"
                        );
                    }
                }
                b')' => parens = parens.saturating_sub(1),
                _ => {}
            }
            i += 1;
        }
    }
    Ok(())
}

/// Refuse a parsed template that uses a partial, partial block, inline partial
/// or decorator anywhere — including inside helper blocks, their `else`
/// branches and subexpressions.
pub(crate) fn refuse_partials(template: &Template) -> Result<()> {
    template.elements.iter().try_for_each(refuse_partials_in)
}

fn refuse_partials_in(element: &TemplateElement) -> Result<()> {
    match element {
        TemplateElement::RawString(_) | TemplateElement::Comment(_) => Ok(()),
        TemplateElement::HtmlExpression(h)
        | TemplateElement::Expression(h)
        | TemplateElement::HelperBlock(h) => {
            for p in std::iter::once(&h.name)
                .chain(h.params.iter())
                .chain(h.hash.values())
            {
                if let Parameter::Subexpression(sub) = p {
                    refuse_partials_in(&sub.element)?;
                }
            }
            for body in [&h.template, &h.inverse].into_iter().flatten() {
                refuse_partials(body)?;
            }
            Ok(())
        }
        TemplateElement::DecoratorExpression(_)
        | TemplateElement::DecoratorBlock(_)
        | TemplateElement::PartialExpression(_)
        | TemplateElement::PartialBlock(_) => bail!(
            "template-partial: partials (`{{{{> name}}}}`, `{{{{#> name}}}}`), inline \
             partials (`{{{{#*inline}}}}`) and decorators are not supported in module \
             templates. Write the repeated text out, or generate it with `{{{{#each}}}}`."
        ),
        // The enum is non-exhaustive: an element kind this walk does not know
        // has not been judged safe, so it is refused rather than rendered.
        _ => bail!("template-unsupported: the template uses an unsupported construct"),
    }
}

/// The largest array or object anywhere in `config`, at least 1: the most
/// times one `{{#each}}` can repeat its body, whichever path it names.
pub(crate) fn largest_collection(config: &serde_json::Value) -> u64 {
    let (len, children): (usize, Box<dyn Iterator<Item = &serde_json::Value> + '_>) = match config {
        serde_json::Value::Array(a) => (a.len(), Box::new(a.iter())),
        serde_json::Value::Object(o) => (o.len(), Box::new(o.values())),
        _ => return 1,
    };
    children
        .map(largest_collection)
        .max()
        .unwrap_or(1)
        .max(len as u64)
        .max(1)
}

/// An upper bound on the element evaluations a render performs: one per
/// element, a block's body and `else` branch once each, and an `each` body
/// `each_len` times. Saturating, so a hostile nest cannot wrap it.
pub(crate) fn render_work(template: &Template, each_len: u64) -> u64 {
    template.elements.iter().fold(0u64, |acc, e| {
        let own = match e {
            TemplateElement::HelperBlock(h) => {
                let body = h.template.as_ref().map_or(0, |t| render_work(t, each_len));
                let inverse = h.inverse.as_ref().map_or(0, |t| render_work(t, each_len));
                let repeats = if h.name.as_name() == Some("each") {
                    each_len
                } else {
                    1
                };
                1u64.saturating_add(body.saturating_mul(repeats))
                    .saturating_add(inverse)
            }
            _ => 1,
        };
        acc.saturating_add(own)
    })
}

/// Parse `source` into a template that is safe to render against `config`:
/// nesting bounded, no partials or decorators, and iteration within
/// [`MAX_RENDER_WORK`].
pub(crate) fn compile_bounded(source: &str, config: &serde_json::Value) -> Result<Template> {
    check_nesting(source)?;
    let template = Template::compile(source)
        .map_err(|e| anyhow::anyhow!("Failed to parse Handlebars template: {e}"))?;
    refuse_partials(&template)?;
    let work = render_work(&template, largest_collection(config));
    if work > MAX_RENDER_WORK {
        bail!(
            "template-too-expensive: `{{{{#each}}}}` over the supplied config would \
             evaluate more than {MAX_RENDER_WORK} template elements. Reduce the nesting \
             of `each` blocks or the size of the config collections."
        );
    }
    Ok(template)
}

/// A writer that refuses to hold more than `cap` bytes, so a render that
/// outgrows its bound stops instead of filling memory.
pub(crate) struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
}

impl CappedWriter {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
        }
    }

    pub(crate) fn into_string(self) -> Result<String> {
        String::from_utf8(self.buf)
            .map_err(|_| anyhow::anyhow!("rendered template is not valid UTF-8"))
    }
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.cap.saturating_sub(self.buf.len()) {
            return Err(std::io::Error::other(format!(
                "rendered template exceeds the {}-byte output cap",
                self.cap
            )));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refusal(source: &str, config: &serde_json::Value) -> String {
        compile_bounded(source, config)
            .expect_err("template must be refused")
            .to_string()
    }

    #[test]
    fn a_self_including_inline_partial_is_refused_before_any_render() {
        let msg = refusal("{{#*inline \"a\"}}x{{> a}}{{/inline}}{{> a}}", &json!({}));
        assert!(msg.starts_with("template-partial"), "got: {msg}");
    }

    #[test]
    fn a_doubling_partial_chain_is_refused() {
        let mut source = String::from("{{#*inline \"p0\"}}x{{/inline}}");
        for i in 1..=30 {
            source.push_str(&format!(
                "{{{{#*inline \"p{i}\"}}}}{{{{> p{prev}}}}}{{{{> p{prev}}}}}{{{{/inline}}}}",
                prev = i - 1
            ));
        }
        source.push_str("{{> p30}}");
        assert!(refusal(&source, &json!({})).starts_with("template-partial"));
    }

    #[test]
    fn every_partial_and_decorator_form_is_refused_wherever_it_sits() {
        for source in [
            "{{> header}}",
            "{{#> layout}}body{{/layout}}",
            "{{*decorate}}",
            "{{#if on}}{{> header}}{{/if}}",
            "{{#if on}}a{{else}}{{> header}}{{/if}}",
            "{{#each items}}{{#if this}}{{> header}}{{/if}}{{/each}}",
        ] {
            let msg = refusal(source, &json!({"on": true, "items": [1]}));
            assert!(msg.starts_with("template-partial"), "{source}: {msg}");
        }
    }

    #[test]
    fn nesting_past_the_bound_is_refused_without_parsing() {
        // Ten thousand levels overflow the stack inside the parser; the scan
        // must answer first.
        for n in [MAX_NESTING_DEPTH + 1, 10_000, 100_000] {
            let blocks = format!("{}x{}", "{{#if a}}".repeat(n), "{{/if}}".repeat(n));
            assert!(refusal(&blocks, &json!({})).starts_with("template-too-deep"));
            let subs = format!("{{{{a {}1{}}}}}", "(a ".repeat(n), ")".repeat(n));
            assert!(refusal(&subs, &json!({})).starts_with("template-too-deep"));
        }
    }

    #[test]
    fn nesting_at_the_bound_and_sequential_blocks_are_accepted() {
        let n = MAX_NESTING_DEPTH;
        let nested = format!("{}x{}", "{{#if a}}".repeat(n), "{{/if}}".repeat(n));
        compile_bounded(&nested, &json!({"a": true})).expect("at the bound");
        // Closed blocks do not accumulate.
        let sequential = "{{#if a}}x{{/if}}".repeat(MAX_NESTING_DEPTH * 10);
        compile_bounded(&sequential, &json!({"a": true})).expect("sequential blocks");
    }

    #[test]
    fn nested_each_over_a_large_collection_is_refused() {
        let items: Vec<u32> = (0..1000).collect();
        let config = json!({ "items": items });
        let source =
            "{{#each items}}{{#each @root.items}}{{#each @root.items}}x{{/each}}{{/each}}{{/each}}";
        assert!(refusal(source, &config).starts_with("template-too-expensive"));
        // One level over the same collection is ordinary.
        compile_bounded("{{#each items}}x{{/each}}", &config).expect("a single each");
    }

    #[test]
    fn the_largest_collection_is_found_at_any_depth() {
        assert_eq!(largest_collection(&json!("s")), 1);
        assert_eq!(largest_collection(&json!({})), 1);
        assert_eq!(largest_collection(&json!({"a": [1, 2, 3]})), 3);
        assert_eq!(
            largest_collection(&json!({"a": {"b": [[1, 2, 3, 4, 5], [1]]}})),
            5
        );
        assert_eq!(largest_collection(&json!({"a": 1, "b": 2, "c": [1]})), 3);
    }

    #[test]
    fn render_work_multiplies_only_through_each() {
        let t = Template::compile("{{#each a}}{{#each a}}x{{/each}}{{/each}}").unwrap();
        // inner: 1 + 1*10 = 11; outer: 1 + 11*10 = 111.
        assert_eq!(render_work(&t, 10), 111);
        let t = Template::compile("{{#if a}}{{#if a}}x{{/if}}{{/if}}").unwrap();
        assert_eq!(render_work(&t, 10), 3);
        let t = Template::compile(
            "{{#each a}}{{#each a}}{{#each a}}{{#each a}}x{{/each}}{{/each}}{{/each}}{{/each}}",
        )
        .unwrap();
        assert_eq!(
            render_work(&t, u64::MAX),
            u64::MAX,
            "saturates, never wraps"
        );
    }

    #[test]
    fn the_capped_writer_stops_at_its_cap() {
        use std::io::Write;
        let mut w = CappedWriter::new(4);
        w.write_all(b"abcd").expect("exactly the cap");
        assert!(w.write_all(b"e").is_err());
        assert_eq!(w.into_string().unwrap(), "abcd");
    }
}
