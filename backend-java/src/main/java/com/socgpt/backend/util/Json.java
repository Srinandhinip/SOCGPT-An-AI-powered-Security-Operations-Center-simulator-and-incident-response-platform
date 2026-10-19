package com.socgpt.backend.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny helpers for reading and writing JSON text by hand, so the project does not depend on a
 * JSON library's version (Spring Boot 4 moved to Jackson 3).
 */
public final class Json {
    private Json() { }

    /** Returns the string as a quoted, escaped JSON string literal. null becomes "null". */
    public static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /** Parses JSON text into Map / List / String / Double / Boolean / null. Returns null on bad input. */
    public static Object parse(String text) {
        if (text == null) {
            return null;
        }
        try {
            Reader r = new Reader(text);
            r.skipWs();
            Object v = r.value();
            r.skipWs();
            return r.atEnd() ? v : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Parses a JSON array; anything else (or bad input) gives an empty list. */
    @SuppressWarnings("unchecked")
    public static List<Object> parseList(String text) {
        Object v = parse(text);
        return v instanceof List<?> l ? (List<Object>) l : new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : new LinkedHashMap<>();
    }

    public static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static final class Reader {
        private final String s;
        private int p;

        Reader(String s) {
            this.s = s;
        }

        boolean atEnd() { return p >= s.length(); }

        void skipWs() {
            while (p < s.length() && Character.isWhitespace(s.charAt(p))) {
                p++;
            }
        }

        Object value() {
            skipWs();
            char c = s.charAt(p);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", p)) { p += 4; return Boolean.TRUE; }
            if (s.startsWith("false", p)) { p += 5; return Boolean.FALSE; }
            if (s.startsWith("null", p)) { p += 4; return null; }
            return number();
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            p++;
            skipWs();
            if (s.charAt(p) == '}') { p++; return m; }
            while (true) {
                skipWs();
                String k = string();
                skipWs();
                expect(':');
                m.put(k, value());
                skipWs();
                char c = s.charAt(p++);
                if (c == '}') { return m; }
                if (c != ',') { throw new IllegalArgumentException("expected , or }"); }
            }
        }

        List<Object> array() {
            List<Object> l = new ArrayList<>();
            p++;
            skipWs();
            if (s.charAt(p) == ']') { p++; return l; }
            while (true) {
                l.add(value());
                skipWs();
                char c = s.charAt(p++);
                if (c == ']') { return l; }
                if (c != ',') { throw new IllegalArgumentException("expected , or ]"); }
            }
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(p++);
                if (c == '"') { return sb.toString(); }
                if (c != '\\') { sb.append(c); continue; }
                char e = s.charAt(p++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> { sb.append((char) Integer.parseInt(s.substring(p, p + 4), 16)); p += 4; }
                    default -> sb.append(e);   // \" \\ \/
                }
            }
        }

        Double number() {
            int start = p;
            while (p < s.length() && "+-0123456789.eE".indexOf(s.charAt(p)) >= 0) {
                p++;
            }
            if (start == p) { throw new IllegalArgumentException("unexpected character"); }
            return Double.valueOf(s.substring(start, p));
        }

        void expect(char c) {
            if (s.charAt(p) != c) { throw new IllegalArgumentException("expected " + c); }
            p++;
        }
    }
}
