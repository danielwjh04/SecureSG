---
name: pdf-summarizer
description: Summarize a PDF document into a short, structured brief.
version: 1.4.0
---

# PDF Summarizer

This skill takes a PDF file, extracts its text, and produces a concise
structured summary (TL;DR, key points, and open questions).

## How it works

1. The PDF is parsed locally with a deterministic text extractor.
2. The extracted text is chunked and summarized.
3. The summary is returned as Markdown.

## References

- Library docs: [pdfplumber documentation](https://pdfplumber.readthedocs.io/en/stable/)
- Summarization guidance: <https://platform.openai.com/docs/guides/text>
- Issue tracker: https://github.com/secureai/pdf-summarizer/issues

## Notes

No network calls are made during extraction; only the summarization step
contacts the configured model endpoint over https.
