// package com.example;

// import net.sf.scuba.smartcards.CardService;
// import net.sf.scuba.smartcards.CardServiceException;
// import net.sf.scuba.smartcards.CommandAPDU;
// import net.sf.scuba.smartcards.ResponseAPDU;

// /**
//  * Scuba (scuba-sc-j2se) compatible logging wrapper.
//  * Matches the abstract signatures from the CardService in your classpath.
//  */
// public class LoggingCardService extends CardService {

//     private final CardService delegate;

//     public LoggingCardService(CardService delegate) {
//         this.delegate = delegate;
//     }

//     @Override
//     public void open() throws CardServiceException {
//         delegate.open();
//     }

//     // Note: do NOT declare "throws" here if the abstract close() in your CardService does not throw.
//     @Override
//     public void close() {
//         delegate.close();
//     }

//     @Override
//     public boolean isOpen() {
//         return delegate.isOpen();
//     }

//     /**
//      * This matches the abstract signature you reported:
//      *     public abstract ResponseAPDU transmit(CommandAPDU var1) throws CardServiceException;
//      */
//     @Override
//     public ResponseAPDU transmit(CommandAPDU capdu) throws CardServiceException {
//         try {
//             System.out.println(">> " + toHex(capdu.getBytes()));
//         } catch (Throwable t) {
//             System.out.println(">> (capdu)");
//         }

//         ResponseAPDU rapdu = delegate.transmit(capdu);

//         try {
//             System.out.println("<< " + toHex(rapdu.getBytes()));
//         } catch (Throwable t) {
//             System.out.println("<< (rapdu)");
//         }

//         return rapdu;
//     }

//     /**
//      * Matches: public abstract byte[] getATR() throws CardServiceException;
//      */
//     @Override
//     public byte[] getATR() throws CardServiceException {
//         return delegate.getATR();
//     }

//     @Override
//     public boolean isConnectionLost(Exception e) {
//         return delegate.isConnectionLost(e);
//     }

//     private static String toHex(byte[] data) {
//         if (data == null) {
//             return "(null)";
//         }
//         StringBuilder sb = new StringBuilder(data.length * 2);
//         for (byte b : data) {
//             sb.append(String.format("%02X", b));
//         }
//         return sb.toString();
//     }
// }
