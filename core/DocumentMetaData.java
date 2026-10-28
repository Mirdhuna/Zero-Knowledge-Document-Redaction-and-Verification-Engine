package core;

import java.io.File;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Represents metadata for a document selected in the engine.
 */
public class DocumentMetaData {
    private final String fileName;
    private final String absolutePath;
    private final long fileSizeBytes;
    private final String fileExtension;
    private final String lastModifiedFormatted;
    private final boolean exists;
    private final boolean readable;

    public DocumentMetaData(File file) {
        if (file != null && file.exists()) {
            this.fileName = file.getName();
            this.absolutePath = file.getAbsolutePath();
            this.fileSizeBytes = file.length();
            this.exists = true;
            this.readable = file.canRead();

            String name = file.getName();
            int dotIdx = name.lastIndexOf('.');
            this.fileExtension = (dotIdx >= 0 && dotIdx < name.length() - 1)
                    ? name.substring(dotIdx + 1).toLowerCase()
                    : "";

            long lastMod = file.lastModified();
            this.lastModifiedFormatted = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault())
                    .format(Instant.ofEpochMilli(lastMod));
        } else {
            this.fileName = file != null ? file.getName() : "Unknown";
            this.absolutePath = file != null ? file.getAbsolutePath() : "";
            this.fileSizeBytes = 0;
            this.fileExtension = "";
            this.lastModifiedFormatted = "-";
            this.exists = false;
            this.readable = false;
        }
    }

    public String getFileName() {
        return fileName;
    }

    public String getAbsolutePath() {
        return absolutePath;
    }

    public long getFileSizeBytes() {
        return fileSizeBytes;
    }

    public String getFormattedSize() {
        if (fileSizeBytes < 1024) {
            return fileSizeBytes + " B";
        } else if (fileSizeBytes < 1024 * 1024) {
            return String.format("%.2f KB", fileSizeBytes / 1024.0);
        } else {
            return String.format("%.2f MB", fileSizeBytes / (1024.0 * 1024.0));
        }
    }

    public String getFileExtension() {
        return fileExtension;
    }

    public String getLastModifiedFormatted() {
        return lastModifiedFormatted;
    }

    public boolean isExists() {
        return exists;
    }

    public boolean isReadable() {
        return readable;
    }

    @Override
    public String toString() {
        return "DocumentMetaData{" +
                "fileName='" + fileName + '\'' +
                ", size=" + getFormattedSize() +
                ", extension='" + fileExtension + '\'' +
                '}';
    }
}
