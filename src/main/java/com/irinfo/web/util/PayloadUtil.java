package com.irinfo.web.util;

/**
 * Extracts a printable-ASCII preview from raw payload bytes.
 */
public class PayloadUtil {

    public static String extractPreview(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            }
        }

        return sb.toString().trim();
    }
}