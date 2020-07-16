package encryptdecrypt;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

interface CodingMethod {

    String encryption(String text);
    String decryption(String text);

}

class ShiftAlgorithm implements CodingMethod {

    final int key;

    public ShiftAlgorithm(int key) {
        this.key = key % 26; // letters come full circle
    }

    @Override
    public String encryption(String text) {
        if (text == null) {
            return "";
        }
        // Replace each letter with another letter shifted by key to the right
        char[] textArr = text.toCharArray();
        for (int i = 0; i < textArr.length; i++) {
            if (Character.isLowerCase(textArr[i])) {
                textArr[i] += key;
                if (textArr[i] > 'z') {
                    textArr[i] -= 26; // loop back to beginning
                }
            } else if (Character.isUpperCase(textArr[i])) {
                textArr[i] += key;
                if (textArr[i] > 'Z') {
                    textArr[i] -= 26; // loop back to beginning
                }
            }
        }
        return new String(textArr);
    }

    @Override
    public String decryption(String text) {
        if (text == null) {
            return "";
        }
        // Replace each letter with another letter shifted by key to the left
        char[] textArr = text.toCharArray();
        for (int i = 0; i < textArr.length; i++) {
            if (Character.isLowerCase(textArr[i])) {
                textArr[i] -= key;
                if (textArr[i] < 'a') {
                    textArr[i] += 26; // loop back to beginning
                }
            } else if (Character.isUpperCase(textArr[i])) {
                textArr[i] -= key;
                if (textArr[i] < 'A') {
                    textArr[i] += 26; // loop back to beginning
                }
            }
        }
        return new String(textArr);
    }
}

class UnicodeAlgorithm implements CodingMethod {

    final int key;

    public UnicodeAlgorithm(int key) {
        this.key = key;
    }

    @Override
    public String encryption(String text) {
        if (text == null) {
            return "";
        }
        // Replace each character with a unicode char, key to the right
        char[] textArr = text.toCharArray();
        for (int i = 0; i < textArr.length; i++) {
            textArr[i] = (char) (textArr[i] + key);
        }
        return new String(textArr);
    }

    @Override
    public String decryption(String text) {
        if (text == null) {
            return "";
        }
        // Replace each character with a unicode char, key to the left
        char[] textArr = text.toCharArray();
        for (int i = 0; i < textArr.length; i++) {
            textArr[i] = (char) (textArr[i] - key);
        }
        return new String(textArr);
    }
}

// CodeMaker processes arguments into a plan to
// send an encrypted or decrypted message to output method
class CodeMaker {
    private CodingMethod algorithmMethod;
    private OutputMethod outputMethod;
    private CodingArguments args;

    public void processTask(CodingArguments args) {
        this.args = args;
        assignAlgorithm();
        setOutputMethod();
        sendTextToOutput();
    }

    public void assignAlgorithm() {
        // set the algorithm to be used
        if (args.getAlgorithm() == AlgorithmType.SHIFT) {
            algorithmMethod = new ShiftAlgorithm(args.getKey());
        } else if (args.getAlgorithm() == AlgorithmType.UNICODE) {
            algorithmMethod = new UnicodeAlgorithm(args.getKey());
        }
    }

    public void setOutputMethod() {
        // set the output method
        if ("".equals(args.getOutput())) {
            outputMethod = new OutputToStream();
        } else {
            outputMethod = new OutputToFile(args.getOutput());
        }
    }

    public void sendTextToOutput() {
        // send transformed text to output
        if (args.getMode() == Mode.DEC) {
            outputMethod.send(algorithmMethod.decryption(args.getData()));
        } else {
            outputMethod.send(algorithmMethod.encryption(args.getData()));
        }
    }
}

interface OutputMethod {
    void send(String text);
}

class OutputToFile implements OutputMethod {

    File outFile;
    public OutputToFile(String fileName) {
        outFile = new File(fileName);
    }

    @Override
    public void send(String text) {
        try (FileWriter writer = new FileWriter(outFile)) {
            writer.write(text);
        } catch (IOException e) {
            System.out.println("Unable to write to file: " + outFile.getPath());
        }
    }
}

class OutputToStream implements OutputMethod {

    @Override
    public void send(String text) {
        System.out.println(text);
    }
}

enum Mode {ENC, DEC}
enum AlgorithmType {SHIFT, UNICODE}

class CodingArguments {
    // Fields determine how to process the data
    private Mode mode = Mode.ENC;
    private static String data = "";
    private AlgorithmType algorithm = AlgorithmType.SHIFT;
    private static int key = 0;
    private static String filePathIn = "";
    private static String filePathOut = "";

    public Mode getMode() {
        return mode;
    }

    public AlgorithmType getAlgorithm() {
        return algorithm;
    }

    public int getKey() {
        return key;
    }

    public String getOutput() {
        return filePathOut;
    }

    public String getData() {
        return data;
    }

    public CodingArguments(String[] args) {
        // Process each argument
        for (int i = 0; i < args.length; i++) {
            if (i + 1 >= args.length) {
                continue; // break out if no following arguments
            }

            switch(args[i]) {
                case "-mode":
                    String modeArg = args[i + 1];
                    if ("dec".equals(modeArg)) {
                        mode = Mode.DEC;
                    } else {
                        mode = Mode.ENC;
                    }
                    break;
                case "-key":
                    key = Integer.parseInt(args[i + 1]);
                    break;
                case "-data":
                    data = args[i + 1];
                    break;
                case "-in":
                    filePathIn = args[i + 1];
                    break;
                case "-out":
                    filePathOut = args[i + 1];
                    break;
                case "-alg":
                    String algArg = args[i + 1];
                    if ("unicode".equals(algArg)) {
                        algorithm = AlgorithmType.UNICODE;
                    } else {
                        algorithm = AlgorithmType.SHIFT;
                    }
                    break;
                default:
                    break;
            }
        }

        // Get data from file if it exists
        if ("".equals(data)) { // If no data, use file
            try {
                data = readFileAsString(filePathIn);
            } catch (IOException e) {
                System.out.println("Error: Input file not found: " + filePathIn);
            }
        }
    }
    public static String readFileAsString(String fileName) throws IOException {
        return new String(Files.readAllBytes(Paths.get(fileName)));
    }
}
public class Main {
    public static void main(String[] args) {
        // Bundle settings from command line and process with CodeMaker
        CodingArguments codingArgs = new CodingArguments(args);
        CodeMaker codeMaker = new CodeMaker();
        codeMaker.processTask(codingArgs);
    }
}
