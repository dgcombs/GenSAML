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
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.BufferedReader;

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
        // create Options object for command line
        Options options = new Options();

        // add h option
        options.addOption("h", false, "You want usage? Don't be ridiculous!");
        options.addOption("u",true,"Target URL");
        options.addOption("k",true,"Base64 Encoded Key File Name");
        //options.addOption("e",true,"Environment - dev, test, prod");
        options.addOption("s",true,"SAML File Name");
        //options.addOption("t",true,"TCID");
        
        CommandLineParser parser = new PosixParser();
        CommandLine cmd = parser.parse( options, args);
        if(cmd.hasOption("h")) {
        // Tell Dan Howdy
            System.out.println("Howdy, Dan!");
            System.exit(0);
        }
        // Get the URL Option
        String targetURL = cmd.getOptionValue("u");
        if (targetURL == null) {
            System.out.println("Target URL Required");
            System.exit(1);
        }
        String encryptionKeyFileName = cmd.getOptionValue("k");
        if (encryptionKeyFileName == null) {
            System.out.println("Encryption Key File Required");
            System.exit(1);
        }
        String samlFileName = cmd.getOptionValue("s");
        if (samlFileName == null) {
            System.out.println("SAML File Required");
            System.exit(1);
        }
        //String tcidValue = cmd.getOptionValue("t");
        //if (tcidValue == null) {
            //System.out.println("TCID Value Required");
            //System.exit(1);
        //}
        
        // Open Key file and read in key
        FileReader keyf = new FileReader(encryptionKeyFileName); 
        BufferedReader br = new BufferedReader(keyf); 
        String encryptionKey; 
        while((encryptionKey = br.readLine()) != null) { 
            System.out.print(".");
            System.out.println("Secret Key:: " + encryptionKey);
        }
        // encryptionKey = encryptionKey.trim();
        keyf.close();
        
        // Open SAML file and read into String variable
        FileReader samlf = new FileReader(samlFileName);
        BufferedReader cr = new BufferedReader(samlf);
        String plainSAML;
        while ((plainSAML = cr.readLine()) != null) {
            System.out.print(".");
        }
        samlf.close();
        
        // Encrypt the SAML
        String encryptedSAML=null;
        byte[] keyBytes = new Base64().decode(encryptionKey);
        System.out.println("Length of Key:: " + new String(keyBytes.length));
        Key secretKey = new SecretKeySpec(keyBytes,"DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherSAML = cipher.doFinal(plainSAML.getBytes("utf-8"));
        cipherSAML = new Base64().encode(cipherSAML);
        
        // Build the HTML File
        String htmlString="<!DOCTYPE HTML>";
        htmlString += "<html>";
        htmlString += "<head>";
        htmlString += "<title>SAML Test Assertion</title>";
        htmlString += "</head>";
        htmlString += "<body onload=\"submit_form();\">\n<form name=\"myform\" action=\"";
        htmlString += targetURL + "\" method=POST\"";
        htmlString += "<input> type=\"hidden\" name=\"SAMLResponse\" value=\"";
        htmlString += new String(cipherSAML) + "\">";
        htmlString += "</form>";
        htmlString += "<script language=\"javascript\">";
		htmlString += "function submit_form() {";
		htmlString += "document.myform.submit()";
		htmlString += "}";
	    htmlString += "</script>";
        htmlString += "</body>";
        htmlString += "</html>";
    }
}