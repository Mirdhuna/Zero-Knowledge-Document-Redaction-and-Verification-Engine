package com.zeroknowledge.document;

import com.zeroknowledge.exception.DocumentProcessingException;
import java.nio.file.Path;

/**
 * Abstraction for reading and validating raw document content from disk.
 */
public interface DocumentReader {

    /**
     * Returns the {@link DocumentFormat} supported by this reader.
     */
    DocumentFormat getSupportedFormat();

    /**
     * Reads and validates the textual content of the document at {@code sourcePath}.
     *
     * @param sourcePath path to the source document
     * @return validated document content string
     * @throws DocumentProcessingException if reading fails, format is invalid, or text extraction is unsupported
     */
    String readValidatedContent(Path sourcePath) throws DocumentProcessingException;
}
