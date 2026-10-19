//! A minimal port of Go's `text/tabwriter` for the settings the CLI uses
//! (`minwidth 0, tabwidth 4, padding 2, padchar ' ', flags 0`), so tables align
//! byte for byte with the Go CLI. Mirrors the copy in `runeward-charter`.

/// Buffers tab-separated text and aligns it on [`TabWriter::flush`].
#[derive(Debug, Default)]
pub struct TabWriter {
    buf: String,
}

const PADDING: usize = 2;

impl TabWriter {
    /// Appends text; cells end at `\t`, lines at `\n`.
    pub fn push(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    /// Aligns the buffered text and appends it to `out`.
    pub fn flush(self, out: &mut String) {
        // Every line but the last is newline-terminated; the last is whatever
        // trails the final newline (usually empty).
        let lines: Vec<Vec<&str>> = self
            .buf
            .split('\n')
            .map(|line| line.split('\t').collect())
            .collect();
        let mut widths = Vec::new();
        format(out, &lines, &mut widths, 0, lines.len());
    }
}

fn cell_width(s: &str) -> usize {
    s.chars().count()
}

/// Go's recursive column-block layout: a column block is a run of
/// consecutive lines that all have a tab-terminated cell in this column.
fn format(
    out: &mut String,
    lines: &[Vec<&str>],
    widths: &mut Vec<usize>,
    mut line0: usize,
    line1: usize,
) {
    let column = widths.len();
    let mut this = line0;
    while this < line1 {
        if column + 1 >= lines[this].len() {
            this += 1;
            continue;
        }
        write_lines(out, lines, widths, line0, this);
        line0 = this;
        let mut width = 0;
        while this < line1 && column + 1 < lines[this].len() {
            width = width.max(cell_width(lines[this][column]) + PADDING);
            this += 1;
        }
        widths.push(width);
        format(out, lines, widths, line0, this);
        widths.pop();
        line0 = this;
    }
    write_lines(out, lines, widths, line0, line1);
}

fn write_lines(out: &mut String, lines: &[Vec<&str>], widths: &[usize], from: usize, to: usize) {
    for (i, line) in lines.iter().enumerate().take(to).skip(from) {
        for (j, cell) in line.iter().enumerate() {
            out.push_str(cell);
            if let Some(&w) = widths.get(j) {
                let pad = w.saturating_sub(cell_width(cell));
                out.extend(std::iter::repeat_n(' ', pad));
            }
        }
        if i + 1 < lines.len() {
            out.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(s: &str) -> String {
        let mut tw = TabWriter::default();
        tw.push(s);
        let mut out = String::new();
        tw.flush(&mut out);
        out
    }

    #[test]
    fn aligns_like_go() {
        assert_eq!(
            render("a\tbb\tc\nlonger\tx\ty\n"),
            "a       bb  c\nlonger  x   y\n"
        );
        // A line without a cell in a column ends that column's block.
        assert_eq!(
            render("a\tb\nno tabs\nlong\tc\n"),
            "a  b\nno tabs\nlong  c\n"
        );
        assert_eq!(render("  é\t= x\t(y)\n"), "  é  = x  (y)\n");
    }
}
