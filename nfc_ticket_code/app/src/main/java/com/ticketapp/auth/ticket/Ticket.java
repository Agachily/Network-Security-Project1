package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;

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

    /** Judge whether the card is within validated time */
    public boolean checkValidationTime(){
        /** Get the current time */
        int currentTime = (int)(System.currentTimeMillis()/1000);
        int beginTime = getBeginTime();
        int validationTime = getValidationTime();
        return (validationTime >= (currentTime-beginTime));
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        String message = "";
        int ridesNumber = getRidesNumber();

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Initialize the card if the rides number is 0 and is not within the validated time
        if (!checkValidationTime() || (ridesNumber == 0)){
            message = "The card has been initialized";
            writeRidesNumber(5);
            writeValidationTime(120);
        } else {
            message = "5 more rides have been added";
            writeRidesNumber(ridesNumber+5);
        }

//        writeValidationTime(0);
//        writeRidesNumber(0);

        // Example of writing:
        //byte[] message = "info".getBytes();
        //res = utils.writePages(message, 0, 6, 1);
        // Set information to show for the user
        if (res) {
            infoToShow = message;
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        int ridesNumber = getRidesNumber();
        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        if (ridesNumber == 5){
            writeRidesNumber(ridesNumber-1);
            writeBeginTime();
        } else if (ridesNumber == 0) {
            infoToShow = "There is no more rides!";
            return false;
        } else {
            if (checkValidationTime()){
                writeRidesNumber(ridesNumber-1);
            } else {
                infoToShow = "You card is expired";
                return false;
            }
        }

//        // Example of reading:
//        byte[] message = new byte[4];
//        res = utils.readPages(6, 1, message, 0);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: success!";
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}