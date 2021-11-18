package com.ticketapp.auth.ticket;

import android.icu.text.IDNA;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;


    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /** Convert  byteArray to int*/
    public static int byteArrayToInt(byte[] b) {
        return b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }

    /** Convert  int to ByteArray*/
    public static byte[] intToByteArray(int a) {
        return new byte[] {
                (byte) ((a >> 24) & 0xFF),
                (byte) ((a >> 16) & 0xFF),
                (byte) ((a >> 8) & 0xFF),
                (byte) (a & 0xFF)
        };
    }

    /** Set number of rides to page 4*/
    public boolean writeRidesNumber(int number){
        boolean result;
        byte[] message = intToByteArray(number);
        result = utils.writePages(message, 0, 4, 1);
        return result;
    }

    /** Get rides number from page 4 */
    public int getRidesNumber(){
        byte[] message = new byte[4];
        utils.readPages(4, 1, message, 0);
        int number = byteArrayToInt(message);
        return number;
    }


    /** Set validity time to page 5*/
    public boolean writeValidationTime(int sec) {
        boolean result;
        byte[] message = intToByteArray(sec);
        result = utils.writePages(message, 0, 5, 1);
        return result;
    }

    /** Get the validation time from page 5*/
    public int getValidationTime(){
        byte[] message = new byte[4];
        utils.readPages(5, 1, message, 0);
        int time = byteArrayToInt(message);
        return time;
    }

    /** Write begin time to page 6 */
    public boolean writeBeginTime() {
        boolean result;
        int time = (int)(System.currentTimeMillis()/1000);
        byte[] message = intToByteArray(time);
        result = utils.writePages(message, 0, 6, 1);
        return result;
    }

    /** Get begin time from page 6 */
    public int getBeginTime() {
        byte[] message = new byte[4];
        utils.readPages(6, 1, message, 0);
        int time = byteArrayToInt(message);
        return time;
    }

    /** Write version number time to page 7 */
    public boolean writeVersionNumber(int versionNumber) {
        boolean result;
        byte[] message = intToByteArray(versionNumber);
        result = utils.writePages(message, 0, 7, 1);
        return result;
    }

    /** Get begin time from page 6 */
    public int getVersionNumber() {
        byte[] message = new byte[4];
        utils.readPages(7, 1, message, 0);
        int versionNumber = byteArrayToInt(message);
        return versionNumber;
    }

    /** Set the hash mac to page 8 */
    public boolean writeHashMac(String beginTime){
        // get hash value with length 42
        String UID = getUID();
        int validationTime = getValidationTime();
        byte[] bytesArray = (UID + validationTime + beginTime).getBytes();
        byte[] cont = macAlgorithm.generateMac(bytesArray);
        // get the first 4
        byte[] hashMac = new byte[4];
        for(int i = 0; i<4; i++){
            hashMac[i] = cont[i];
        }
        // write to page 8
        boolean result;
        result = utils.writePages(hashMac, 0, 8, 1);
        return result;
    }

    /** Get the hash value from page 8 */
    public boolean checkHashMac(String beginTime){
        // Get the hash mac in the card
        byte[] hashMacInCard = new byte[4];
        utils.readPages(8, 1, hashMacInCard, 0);
        // Calculate hash mac
        String UID = getUID();
        int validationTime = getValidationTime();
        byte[] bytesArray = (UID + validationTime + beginTime).getBytes();
        byte[] cont = macAlgorithm.generateMac(bytesArray);
        // get the first 4
        for(int i = 0; i<4; i++){
            if(hashMacInCard[i] != cont[i]){
                return false;
            }
        }
        return true;
    }

    /** Judge whether the card is within validated time */
    public boolean checkValidationTime(){
        /** Get the current time */
        int currentTime = (int)(System.currentTimeMillis()/1000);
        int beginTime = getBeginTime();
        int validationTime = getValidationTime();
        return (validationTime >= (currentTime-beginTime));
    }
    public void setProtectedRange() {
        byte[] message = new byte[4];
        message[0] = 30;
        message[1] = 0;
        message[2] = 0;
        message[3] = 0;
        utils.writePages(message, 0, 42, 1);
    }

    /** Get the uid from page 1 */
    public String getUID(){
        byte[] message1 = new byte[4];
        byte[] message2 = new byte[4];
        byte[] result = new byte[7];
        utils.readPages(0, 1, message1, 0);
        utils.readPages(1, 1, message2, 0);
        for(int i = 0; i<3; i++){
            result[i] = message1[i];
            result[i+4] = message2[i];
        }
        result[6] = message2[3];
        String UID = new String(result);
        return UID;
    }

    /** Get the hashcode according to the UID and master key */
    public byte[] getHash() {
        String UID = getUID();
        String passwordToHash = new String(authenticationKey) + UID;
        byte[] res = new byte[16];
        try {

            MessageDigest md = MessageDigest.getInstance("MD5");

            md.update(passwordToHash.getBytes());
            //Get the hash's bytes
            res = md.digest();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        return  res;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        String message = "--";
        int ridesNumber = getRidesNumber();
        byte[] passHash = getHash();
        int versionNUmber = getVersionNumber();


        /** Judge whether the card is blank and authentication*/
        if(versionNUmber == 0){
            if(utils.authenticate(defaultAuthenticationKey)){
                utils.writePages(passHash, 0, 44, 4);
                setProtectedRange();
                writeVersionNumber(5);
            } else {
                infoToShow = "Wrong card";
                return false;
            }
        } else {
            boolean authentication = utils.authenticate(passHash);
            if (!authentication){
                infoToShow = "Authentication failed!";
                return false;
            }
        }
        /** Initialize the card */
        if (!checkValidationTime() || (ridesNumber == 0)){
            writeRidesNumber(5);
            writeValidationTime(120);

            writeHashMac("");
            message = "The card has been initialized";
        } else { // add 5 rides number
            writeRidesNumber(ridesNumber+5);
            message = "5 more rides have been added";
        }

//        byte[] passHash = getHash();
//        utils.authenticate(passHash);
//        writeHashMac("");
//        if(checkHashMac("")){
//            message = "Hash mac check success";
//        }

        infoToShow = message;
        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        String message = "--";
        int ridesNumber = getRidesNumber();
        byte[] passHash = getHash();
        int beginTime = getBeginTime();
        // Authenticate
        res = utils.authenticate(passHash);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        if (checkHashMac(""))
        {
            writeRidesNumber(ridesNumber-1);
            writeBeginTime();
            int beginTime2 = getBeginTime();
            writeHashMac(beginTime2+"");
        } else if(checkHashMac(beginTime+"")) {
            if (checkValidationTime()) {
                if(ridesNumber > 0) {
                    writeRidesNumber(ridesNumber-1);
                } else  {
                    infoToShow = "There is no more rides";
                    return false;
                }
            } else {
                infoToShow = "You card is expired";
                return false;
            }
        }

//        if (ridesNumber == 5){
//            writeRidesNumber(ridesNumber-1);
//            writeBeginTime();
//        } else if (ridesNumber == 0) {
//            infoToShow = "There is no more rides!";
//            return false;
//        } else {
//            if (checkValidationTime()){
//                writeRidesNumber(ridesNumber-1);
//            } else {
//                infoToShow = "You card is expired";
//                return false;
//            }
//        }

        infoToShow = message;

        return true;
    }
}