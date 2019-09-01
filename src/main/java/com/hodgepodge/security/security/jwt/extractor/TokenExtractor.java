package com.hodgepodge.security.security.jwt.extractor;

import javax.servlet.http.HttpServletRequest;

public interface TokenExtractor {

    String extract(final HttpServletRequest request);
}
