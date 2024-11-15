import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class utils {
    /**
     * Reads the content of a file and returns it as a byte array.
     *
     * @param file the file to read
     * @return a byte array containing the content of the file
     * @throws IllegalArgumentException if the file does not exist
     * @throws RuntimeException if an error occurs while reading the file
     */
    public static byte[] readContent(File file) {
        if (!file.isFile() || !file.exists()) {
            throw new IllegalArgumentException("File does not exist: " + file.getPath());
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Reads the content of a file and returns it as a string.
     *
     * @param file the file to read
     * @return a string containing the content of the file
     * @throws IllegalArgumentException if the file does not exist
     * @throws RuntimeException if an error occurs while reading the file
     */
    public static String readContentAsString(File file) {
        return new String(readContent(file));
    }


}