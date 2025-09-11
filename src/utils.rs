#[derive(Debug)]
pub struct OffsetSource<S: miette::SourceCode> {
    source: S,
    line_offset: usize,
}

impl<S> OffsetSource<S>
where
    S: miette::SourceCode,
{
    pub fn new(source: S) -> Self {
        Self {
            source,
            line_offset: 0,
        }
    }

    pub fn new_named(name: impl AsRef<str>, source: S) -> OffsetSource<miette::NamedSource<S>> {
        OffsetSource::new(miette::NamedSource::new(name, source))
    }

    pub fn with_line_offset(mut self, line_offset: usize) -> Self {
        self.line_offset = line_offset;
        self
    }
}

impl<S> miette::SourceCode for OffsetSource<S>
where
    S: miette::SourceCode,
{
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        let contents = self
            .source
            .read_span(span, context_lines_before, context_lines_after)?;
        let contents = if let Some(name) = contents.name() {
            miette::MietteSpanContents::new_named(
                name.into(),
                contents.data(),
                *contents.span(),
                self.line_offset + contents.line(),
                contents.column(),
                contents.line_count(),
            )
        } else {
            miette::MietteSpanContents::new(
                contents.data(),
                *contents.span(),
                self.line_offset + contents.line(),
                contents.column(),
                contents.line_count(),
            )
        };
        Ok(Box::new(contents))
    }
}
