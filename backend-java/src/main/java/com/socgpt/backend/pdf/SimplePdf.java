package com.socgpt.backend.pdf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A tiny PDF writer (no library). A4 pages, the three built-in fonts (Helvetica, Helvetica-Bold,
 * Courier) with WinAnsi encoding, word-wrapped text, filled rectangles, automatic page breaks and a
 * "Page x of y" footer. Coordinates passed in are measured from the TOP of the page, in points.
 */
public class SimplePdf {

    public static final int HELV = 0, BOLD = 1, MONO = 2;

    public static final float W = 595.28f, H = 841.89f;
    public static final float MARGIN = 44f;
    private static final float BOTTOM = 52f;   // room for the footer

    private static final Charset CP1252 = Charset.forName("windows-1252");

    // Helvetica advance widths for ASCII 32..126 (per 1000 em), from the standard AFM metrics
    private static final int[] HELV_W = {
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584
    };
    private static final int[] BOLD_W = {
        278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
        975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
        333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
        611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584
    };

    private final List<StringBuilder> pages = new ArrayList<>();
    private StringBuilder cur;
    private float y;   // cursor, measured from the top
    private String footerLeft = "";

    public SimplePdf() {
        newPage();
    }

    public void setFooterLeft(String text) {
        this.footerLeft = text == null ? "" : text;
    }

    // ---------------------------------------------------------------- cursor / pages

    public float y() { return y; }

    public void setY(float y) { this.y = y; }

    public void gap(float h) { y += h; }

    public float contentWidth() { return W - 2 * MARGIN; }

    public void newPage() {
        cur = new StringBuilder();
        pages.add(cur);
        y = MARGIN;
    }

    /** Starts a new page if fewer than h points remain. Returns true when it did. */
    public boolean ensure(float h) {
        if (y + h > H - BOTTOM) {
            newPage();
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- drawing

    public void fillRect(float x, float top, float w, float h, int rgb) {
        cur.append(color(rgb, false)).append(num(x)).append(' ').append(num(H - top - h)).append(' ')
           .append(num(w)).append(' ').append(num(h)).append(" re f\n");
    }

    public void strokeRect(float x, float top, float w, float h, int rgb, float lineWidth) {
        cur.append(color(rgb, true)).append(num(lineWidth)).append(" w ")
           .append(num(x)).append(' ').append(num(H - top - h)).append(' ')
           .append(num(w)).append(' ').append(num(h)).append(" re S\n");
    }

    public void hLine(float x1, float x2, float top, int rgb, float lineWidth) {
        cur.append(color(rgb, true)).append(num(lineWidth)).append(" w ")
           .append(num(x1)).append(' ').append(num(H - top)).append(" m ")
           .append(num(x2)).append(' ').append(num(H - top)).append(" l S\n");
    }

    /** One line of text; baselineTop is measured from the top of the page. */
    public void text(String s, int font, float size, int rgb, float x, float baselineTop) {
        s = sanitize(s);
        if (s.isEmpty()) {
            return;
        }
        cur.append("BT ").append(color(rgb, false)).append('/').append(fontName(font)).append(' ').append(num(size))
           .append(" Tf ").append(num(x)).append(' ').append(num(H - baselineTop)).append(" Td (")
           .append(escape(s)).append(") Tj ET\n");
    }

    public void textRight(String s, int font, float size, int rgb, float rightX, float baselineTop) {
        text(s, font, size, rgb, rightX - width(s, font, size), baselineTop);
    }

    /** Flowing paragraph at the cursor; breaks pages as needed and moves the cursor down. */
    public void paragraph(String s, int font, float size, int rgb, float x, float maxWidth, float leading) {
        for (String line : wrap(s, font, size, maxWidth)) {
            ensure(leading);
            text(line, font, size, rgb, x, y + size);
            y += leading;
        }
    }

    // ---------------------------------------------------------------- measuring / wrapping

    public static float width(String s, int font, float size) {
        s = sanitize(s);
        int total = 0;
        for (int i = 0; i < s.length(); i++) {
            total += charWidth(s.charAt(i), font);
        }
        return total * size / 1000f;
    }

    private static int charWidth(char c, int font) {
        if (font == MONO) {
            return 600;
        }
        int[] t = font == BOLD ? BOLD_W : HELV_W;
        if (c >= 32 && c <= 126) {
            return t[c - 32];
        }
        return font == BOLD ? 611 : 556;
    }

    public static List<String> wrap(String text, int font, float size, float maxWidth) {
        List<String> out = new ArrayList<>();
        String clean = sanitize(text);
        for (String para : clean.split("\n", -1)) {
            if (para.isBlank()) {
                out.add("");
                continue;
            }
            StringBuilder line = new StringBuilder();
            for (String word : para.trim().split("\\s+")) {
                // a single very long word (an IP list, a hash) is split by characters
                while (width(word, font, size) > maxWidth) {
                    int cut = 1;
                    while (cut < word.length() && width(word.substring(0, cut + 1), font, size) <= maxWidth) {
                        cut++;
                    }
                    if (line.length() > 0) {
                        out.add(line.toString());
                        line.setLength(0);
                    }
                    out.add(word.substring(0, cut));
                    word = word.substring(cut);
                }
                String candidate = line.length() == 0 ? word : line + " " + word;
                if (width(candidate, font, size) <= maxWidth) {
                    line.setLength(0);
                    line.append(candidate);
                } else {
                    out.add(line.toString());
                    line.setLength(0);
                    line.append(word);
                }
            }
            if (line.length() > 0) {
                out.add(line.toString());
            }
        }
        return out;
    }

    /** Replaces characters the built-in fonts cannot show (arrows, curly quotes, emoji ...). */
    public static String sanitize(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '→' -> sb.append("->");
                case '←' -> sb.append("<-");
                case '≥' -> sb.append(">=");
                case '≤' -> sb.append("<=");
                case '‘', '’' -> sb.append('\'');
                case '“', '”' -> sb.append('"');
                case '–', '—', '−' -> sb.append('-');
                case '…' -> sb.append("...");
                case ' ', '\t' -> sb.append(' ');
                case '\r' -> { }
                case '•' -> sb.append('•');
                default -> {
                    if (c == '\n' || (c >= 32 && c < 127)) {
                        sb.append(c);
                    } else if (c >= 160 && c <= 255) {
                        sb.append(c);     // Latin-1 supplement is identical in WinAnsi
                    } else if (Character.isSurrogate(c)) {
                        if (Character.isHighSurrogate(c)) {
                            sb.append('?');
                        }
                    } else if (CP1252.newEncoder().canEncode(c) && c > 31) {
                        sb.append(c);
                    } else if (c < 32) {
                        sb.append(' ');
                    } else {
                        sb.append('?');
                    }
                }
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- output

    public byte[] toBytes() {
        int total = pages.size();
        for (int i = 0; i < total; i++) {
            StringBuilder page = pages.get(i);
            hLineOn(page, MARGIN, W - MARGIN, H - (H - BOTTOM + 12), 0xD5DAE3);
            textOn(page, footerLeft, HELV, 8, 0x7A8599, MARGIN, H - (H - BOTTOM + 26));
            String right = "Page " + (i + 1) + " of " + total;
            textOn(page, right, HELV, 8, 0x7A8599, W - MARGIN - width(right, HELV, 8), H - (H - BOTTOM + 26));
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> offsets = new ArrayList<>();
        write(out, "%PDF-1.4\n%âãÏÓ\n");

        int pageObjStart = 6;     // objects 1-5 are catalog, pages, 3 fonts
        List<Integer> kids = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            kids.add(pageObjStart + 2 * i);
        }

        obj(out, offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
        StringBuilder k = new StringBuilder();
        for (int id : kids) {
            k.append(id).append(" 0 R ");
        }
        obj(out, offsets, 2, "<< /Type /Pages /Kids [" + k + "] /Count " + total + " >>");
        obj(out, offsets, 3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        obj(out, offsets, 4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
        obj(out, offsets, 5, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>");

        for (int i = 0; i < total; i++) {
            int pageId = pageObjStart + 2 * i, contentId = pageId + 1;
            obj(out, offsets, pageId, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + num(W) + " " + num(H) + "] "
                + "/Resources << /Font << /F0 3 0 R /F1 4 0 R /F2 5 0 R >> >> /Contents " + contentId + " 0 R >>");
            byte[] content = pages.get(i).toString().getBytes(StandardCharsets.ISO_8859_1);
            offsets.add(out.size());
            write(out, contentId + " 0 obj\n<< /Length " + content.length + " >>\nstream\n");
            out.write(content, 0, content.length);
            write(out, "\nendstream\nendobj\n");
        }

        int xref = out.size();
        int count = pageObjStart + 2 * total;
        write(out, "xref\n0 " + count + "\n0000000000 65535 f \n");
        for (int off : offsets) {
            write(out, String.format("%010d 00000 n \n", off));
        }
        write(out, "trailer\n<< /Size " + count + " /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n");
        return out.toByteArray();
    }

    private void obj(ByteArrayOutputStream out, List<Integer> offsets, int id, String body) {
        offsets.add(out.size());
        write(out, id + " 0 obj\n" + body + "\nendobj\n");
    }

    private static void write(ByteArrayOutputStream out, String s) {
        byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
        out.write(b, 0, b.length);
    }

    // ---------------------------------------------------------------- low level

    private void hLineOn(StringBuilder page, float x1, float x2, float pdfY, int rgb) {
        page.append(color(rgb, true)).append("0.6 w ").append(num(x1)).append(' ').append(num(pdfY)).append(" m ")
            .append(num(x2)).append(' ').append(num(pdfY)).append(" l S\n");
    }

    private void textOn(StringBuilder page, String s, int font, float size, int rgb, float x, float pdfY) {
        s = sanitize(s);
        if (s.isEmpty()) {
            return;
        }
        page.append("BT ").append(color(rgb, false)).append('/').append(fontName(font)).append(' ').append(num(size))
            .append(" Tf ").append(num(x)).append(' ').append(num(pdfY)).append(" Td (")
            .append(escape(s)).append(") Tj ET\n");
    }

    private static String fontName(int font) {
        return font == BOLD ? "F1" : font == MONO ? "F2" : "F0";
    }

    private static String color(int rgb, boolean stroke) {
        return num(((rgb >> 16) & 0xFF) / 255f) + " " + num(((rgb >> 8) & 0xFF) / 255f) + " "
            + num((rgb & 0xFF) / 255f) + (stroke ? " RG " : " rg ");
    }

    private static String num(float f) {
        String s = String.format(java.util.Locale.ROOT, "%.2f", f);
        if (s.indexOf('.') >= 0) {
            s = s.replaceAll("0+$", "").replaceAll("\\.$", "");
        }
        return s.isEmpty() || s.equals("-0") ? "0" : s;
    }

    /** Encodes to WinAnsi bytes (as chars 0-255) and escapes the PDF string delimiters. */
    private static String escape(String s) {
        byte[] bytes = s.getBytes(CP1252);
        StringBuilder sb = new StringBuilder(bytes.length + 8);
        for (byte b : bytes) {
            int c = b & 0xFF;
            if (c == '(' || c == ')' || c == '\\') {
                sb.append('\\').append((char) c);
            } else if (c < 32 || c > 126) {
                sb.append('\\').append(String.format("%03o", c));
            } else {
                sb.append((char) c);
            }
        }
        return sb.toString();
    }
}
