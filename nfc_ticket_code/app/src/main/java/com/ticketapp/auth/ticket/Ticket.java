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

    /** Set a max number of rides to specific page */
    private boolean writeMaxRidesNumber(int number){
        boolean result;
        byte[] message = intToByteArray(number);
        result = utils.writePages(message, 0, 4, 1);

        return result;
    }

    /** Get rides number from specific page */
    private int getMaxRidesNumber(){
        byte[] message = new byte[4];
        utils.readPages(4, 1, message, 0);

        int number = byteArrayToInt(message);
        return number;
    }

    /** Set validity time to page 5*/
    private boolean writeValidationTime(int sec) {
        boolean result;
        byte[] message = intToByteArray(sec);
        result = utils.writePages(message, 0, 5, 1);

        return result;
    }

    /** Get the validation time from page 5*/
    private int getValidationTime(){
        byte[] message = new byte[4];
        utils.readPages(5, 1, message, 0);

        int time = byteArrayToInt(message);
        return time;
    }

    /** Write begin time to page 6 */
    private boolean writeBeginTime(int time) {
        boolean result;
        byte[] message = intToByteArray(time);
        result = utils.writePages(message, 0, 6, 1);

        return result;
    }

    /** Get begin time from page 6 */
    private int getBeginTime() {
        byte[] message = new byte[4];
        utils.readPages(6, 1, message, 0);

        int time = byteArrayToInt(message);
        return time;
    }

    /** Write version number time to page 7 */
    private boolean writeVersionNumber(int versionNumber) {
        boolean result;
        byte[] message = intToByteArray(versionNumber);
        result = utils.writePages(message, 0, 7, 1);

        return result;
    }

    /** Get VersionNumber from page 7 */
    private int getVersionNumber() {
        byte[] message = new byte[4];

        utils.readPages(7, 1, message, 0);

        int versionNumber = byteArrayToInt(message);
        return versionNumber;
    }

    /** Calculate hash mac use UID, validationTime, beginTime, maxRidesNumber and counter */
    private byte[] CalculateHashMac(String beginTime, int expectedCounter) {
        // get hash value with length 42
        String UID = getUID();
        int validationTime = getValidationTime();
        int maxRidesNumber = getMaxRidesNumber();
        byte[] bytesArray = (UID + validationTime + beginTime + maxRidesNumber + expectedCounter).getBytes();
        byte[] cont = macAlgorithm.generateMac(bytesArray);
        // get the first 4
        byte[] hashMac = new byte[4];
        for(int i = 0; i<4; i++){
            hashMac[i] = cont[i];
        }
        return hashMac;
    }

    /** Set the hash mac to page 8 */
    private boolean writeHashMac(String beginTime, int expectedCounter ,boolean flag){
        // get hashmac
        byte[] hashMac = CalculateHashMac(beginTime, expectedCounter);

        // write to page 8
        boolean result;
        if(flag) {
            result = utils.writePages(hashMac, 0, 8, 1);
        } else {
            result = utils.writePages(hashMac, 0, 18, 1);
        }
        return result;
    }

    /** Get the hash value from page 8 */
    private boolean checkHashMac(String beginTime,int expectedCounter, boolean flag){
        // Get the hash mac in the card
        byte[] hashMacInCard = new byte[4];
        if(flag) {
            utils.readPages(8, 1, hashMacInCard, 0);
        } else {
            utils.readPages(18, 1, hashMacInCard, 0);
        }
        byte[] hashMac = CalculateHashMac(beginTime, expectedCounter);
        // compare the hashmac between calculated and card hashmac
        for(int i = 0; i<4; i++){
            if(hashMacInCard[i] != hashMac[i]){
                return false;
            }
        }
        return true;
    }

    /** Judge whether the card is within validated time */
    private boolean checkValidationTime(){
        /** Get the current time */
        int currentTime = (int)(System.currentTimeMillis()/1000);
        int beginTime = getBeginTime();
        int validationTime = getValidationTime();
        return (validationTime >= (currentTime-beginTime));
    }

    /** Set protect page from 3 to the end */
    private void setProtectedRange() {
        byte[] message = new byte[4];
        message[0] = 48;
        message[1] = 0;
        message[2] = 0;
        message[3] = 0;
        utils.writePages(message, 0, 42, 1);
    }

    /** Get the uid from page 1 */
    private String getUID(){
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

    /** Increase the counter */
    private boolean increaseCounter(){
        byte[] message = new byte[4];
        message[0] = 1;
        message[1] = 0;
        message[2] = 0;
        message[3] = 0;
        boolean res = utils.writePages(message, 0, 41, 1);
        return res;
    }

    /** Get the counter*/
    private int getCounter() {
        byte[] message = new byte[4];
        utils.readPages(41, 1, message, 0);
        byte[] reverseMessage = new byte[4];
        for(int i = 0; i < 4; i++)
        {
            reverseMessage[i] = message[3 - i];
        }
        return byteArrayToInt(reverseMessage);
    }

    /** Get the hashcode according to the UID and master key */
    private byte[] getHash() {
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

    /** Write log to specific zone. 0 -> use, 1 -> issue, 2 -> plus */
    private void writeLog(int currentTime, int type){
        // get the content in 33 page
        byte[] message = new byte[4];
        utils.readPages(33, 1, message, 0);
        int logCounter = byteArrayToInt(message);
        /** Log the last 3 information to page 34-35, 36-37, 38-39 */
        int zoneNumber = logCounter%3;
        byte[] dataMessage = intToByteArray(currentTime);
        byte[] timeMessage = intToByteArray(type);
        utils.writePages(dataMessage, 0, (zoneNumber*2+34), 1);
        utils.writePages(timeMessage, 0, (zoneNumber*2+35), 1);
        utils.writePages(intToByteArray(logCounter+1),0, 33, 1);
    }

    /** Get the time of latest logtime */
    private int getLogTime(){
        byte[] message = new byte[4];
        utils.readPages(33, 1, message, 0);
        int latestLog = byteArrayToInt(message);

        byte[] latestTime = new byte[4];
        utils.readPages(((latestLog-1)%3)*2+34, 1, latestTime, 0);
        return byteArrayToInt(latestTime);
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        String message = "--";
        // get password Hash
        byte[] passHash = getHash();

        /** Judge whether the card is blank and authentication*/
        if(utils.authenticate(defaultAuthenticationKey)){
            int versionNumber = getVersionNumber();
            if(versionNumber == 0){
                utils.writePages(passHash, 0, 44, 4);
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

        boolean flag = true;
        int maxRidesNumber = getMaxRidesNumber();
        int counter = getCounter();
        int currentTime = (int)(System.currentTimeMillis()/1000);

        /** When the flag is true write hashMac to page 8. Otherwise, the flag is false, write hashMac to page 18 */
        if(counter%2 != 0) {flag = false;}
        /** Initialize the card */
        if (!checkValidationTime() || (maxRidesNumber == counter)){
            setProtectedRange();
            writeMaxRidesNumber(counter + 5);
            writeValidationTime(120);
            writeHashMac("", counter, flag);

            writeLog(currentTime, 1);
            message = "The card has been initialized";
        } else {
            /** add 5 more rides number, when the card is not expired*/
            int beginTime = getBeginTime();
            writeMaxRidesNumber(maxRidesNumber + 5);
            writeHashMac(beginTime+"", counter, flag);

            writeLog(currentTime, 2);
            message = "5 more rides have been added";
        }

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
        byte[] passHash = getHash();

        // Authenticate
        res = utils.authenticate(passHash);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        int maxRidesNumber = getMaxRidesNumber();
        int beginTime = getBeginTime();
        boolean flag = true;
        int counter = getCounter();

        /** If flag is true write hashMac to page 8. Otherwise, if the flag is false, write hashMac to page 18 */
        if(counter%2 != 0) {flag = false;}
        /** check previous hash mac to prevent Man in the middle attacks*/
        if (checkHashMac("", counter, flag))
        {
            int validationTime = getValidationTime();
            if (validationTime > 100000){
                message = "Wired Card!";
            } else {
                message = "Remain： " + (maxRidesNumber - counter - 1);
            }

            int BeginTime2 = (int)(System.currentTimeMillis()/1000);
            writeBeginTime(BeginTime2);
            writeHashMac(BeginTime2+"",counter + 1, !flag);
            writeLog(BeginTime2,0 );
            increaseCounter();
        } else if(checkHashMac(beginTime+"", counter, flag)) {
            if (checkValidationTime()) {
                counter = getCounter();
                if(maxRidesNumber > counter) {
                    int currentTime = (int)(System.currentTimeMillis()/1000);
                    /** If the user tap the card twice within 2 seconds, remind the user and operator */
                    int timeGap = currentTime - getLogTime();
                    if(timeGap < 2){
                        message = "Too fast tap! Maybe Danger";
                    } else {
                        message = "Remain: " + (maxRidesNumber - counter - 1);
                    }
                    writeHashMac(beginTime+"",counter + 1, !flag);
                    writeLog(currentTime, 0);
                    increaseCounter();
                } else  {
                    infoToShow = "There is no more rides";
                    return false;
                }
            } else {
                infoToShow = "You card is expired";
                return false;
            }
        }

        infoToShow = message;

        return true;
    }
}