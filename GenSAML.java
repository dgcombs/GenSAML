/*
** GenSAML - Generate an Encrypted SAML Assertion
** Wrapped in HTML
** Wrapped in an Enigma
**
** Dan McGinn-Combs, 2011 (c)
**
*/

// Command Line Parser
import org.apache.commons.cli.*;

// File IO
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.BufferedWriter;

// Encryption & Decryption
import java.security.Key;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class GenSAML {

    public static void main(String[] args) throws Exception {
        // create Options object
        Options options = new Options();

        // add h option
        options.addOption("h", false, "Display Howdy, Dan!");
        CommandLineParser parser = new PosixParser();
        CommandLine cmd = parser.parse( options, args);
        if(cmd.hasOption("t")) {
        // Tell Dan Howdy
            System.out.println("Howdy, Dan!");
        }
        else {
        // print the date
            System.out.println("No commandline");
        }
    }
}