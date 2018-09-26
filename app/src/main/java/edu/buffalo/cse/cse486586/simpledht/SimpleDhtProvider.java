package edu.buffalo.cse.cse486586.simpledht;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    //https://stackoverflow.com/questions/3887476/how-to-declare-a-dynamic-object-array-in-java?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
    ArrayList<String> keys = new ArrayList<String>();
    static final String TAG = "shahyash";
    static final String REMOTE_PORT0 = "11108";
    static final String REMOTE_PORT1 = "11112";
    static final String REMOTE_PORT2 = "11116";
    static final String REMOTE_PORT3 = "11120";
    static final String REMOTE_PORT4 = "11124";
    static final int SERVER_PORT = 10000;
    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";
    static String minePort;
    String meraLambaPort;
    ArrayList<String> hashedPortAlive = new ArrayList<String>();
    ArrayList<String> portAlive = new ArrayList<String>();
    ArrayList<String> test = new ArrayList<String>();
    static HashMap<String, String> portMap = new HashMap<String, String>();
    String aage, peeche;
    String mineHashedPort;
    int tempNo;

    @Override
    public boolean onCreate() {
        TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        minePort = portStr;
        meraLambaPort = myPort;
        String test;
        try {
            mineHashedPort = genHash(minePort);
            test = genHash("L4ak8qMXYWWQthyTpBdRiG55lpuxJS6L");
            Log.i(TAG, "onCreate: mera hashed port: " + test);
        }
        catch (NoSuchAlgorithmException e) {}
        Log.i(TAG, "onCreate: in oncreate");
        portAlive.add(minePort);
        hashedPortAlive.add(mineHashedPort);
        Log.i(TAG, "onCreate: mera hashed port: " + mineHashedPort);
        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }

        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, minePort, "init");
        return false;
    }

    public boolean isThisTheNode(String hashedKey) {
        try {
            if (aage == null)
                return true;
            else if (mineHashedPort.compareTo(hashedKey) >= 0 && genHash(peeche).compareTo(hashedKey) < 0)
                return true;
            else if (mineHashedPort.equals(hashedPortAlive.get(0)) && mineHashedPort.compareTo(hashedKey) >= 0)
                return true;
            else if (mineHashedPort.equals(hashedPortAlive.get(0)) && hashedKey.compareTo(genHash(peeche)) > 0)
                return true;
            else
                return false;
        }
        catch (NoSuchAlgorithmException e) {}
        return false;
    }

    public void calcPnS() {
        try {
            String myHashedPort = genHash(minePort);
            int size = hashedPortAlive.size();
            Collections.sort(hashedPortAlive);
            Log.i(TAG, "calcPnS: size yeh hai: " + size);
            if (size == 1) {
                return;
            }
            for (int i = 0; i < size; i++) {
                if (myHashedPort.equals(hashedPortAlive.get(i))) {
                    if (i == 0) {
                        aage = portMap.get(hashedPortAlive.get(i + 1));
                        peeche = portMap.get(hashedPortAlive.get(size-1));
                    }
                    else if (i == (size-1)) {
                        aage = portMap.get(hashedPortAlive.get(0));
                        peeche = portMap.get(hashedPortAlive.get(i - 1));
                    }
                    else {
                        aage = portMap.get(hashedPortAlive.get(i + 1));
                        peeche = portMap.get(hashedPortAlive.get(i - 1));
                    }
                }
            }
            Log.i(TAG, "calcPnS: aage: " + aage + " peeche: " + peeche);
        }
        catch (NoSuchAlgorithmException e) {}
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            /*
             * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().
             */
            ServerSocket serverSocket = sockets[0];
            Socket clientSocket;
            DataInputStream msgIn;
            String msgReceived;
            try {
                clientSocket = serverSocket.accept();
                msgIn = new DataInputStream(clientSocket.getInputStream());
                while((msgReceived = msgIn.readUTF()) != null) {
                    if (msgReceived.contains(":")) {
                        Log.i(TAG, "doInBackground: 1st time msg received: " + msgReceived);
                        String[] splitMsg = msgReceived.split(":");
                        portAlive.add(splitMsg[1]);
                        try {
                            hashedPortAlive.add(genHash(splitMsg[1]));
                            portMap.put(genHash(splitMsg[1]), splitMsg[1]);
                            Collections.sort(hashedPortAlive);
                            calcPnS();
                        }catch (NoSuchAlgorithmException e) {}
                        Log.i(TAG, "doInBackground: 5554 ke portAlive me add kiya: " + splitMsg[1]);
                        String msgToSend = "";
                        for (String port : portAlive) {
                            msgToSend = msgToSend + port + "~";
                        }
                        Log.i(TAG, "doInBackground: yeh bheja hai re me: " + msgToSend);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend, "re");
                    }
                    if (msgReceived.contains("~")) {
                        String[] splitMsg = msgReceived.split("~");
                        Log.i(TAG, "doInBackground: ~ iske undar hu: " + msgReceived);
                        for (String splitS : splitMsg) {
                            if (!portAlive.contains(splitS)) {
                                portAlive.add(splitS);
                                Log.i(TAG, "doInBackground: for loop ne portAlive me add kiya: " + splitS);
                                try {
                                    hashedPortAlive.add(genHash(splitS));
                                    Log.i(TAG, "doInBackground: this port wolo: " + splitS + " = " + genHash(splitS));
                                } catch (NoSuchAlgorithmException e) {
                                    Log.d(TAG, "doInBackground: " + e);
                                }
                                hashedPortAlive.trimToSize();
                            }
                            try {
                                portMap.put(genHash(splitS), splitS);
                            }
                            catch (NoSuchAlgorithmException e) {}
                            Collections.sort(hashedPortAlive);
                            calcPnS();
                            Log.i(TAG, "doInBackground: alive nodes: " + Arrays.toString(portAlive.toArray()));
                        }
                        tempNo = hashedPortAlive.size();
                    }
                    if (msgReceived.contains("_")) {
                        Log.i(TAG, "doInBackground: yeh peeche se mila: " + msgReceived);
                        Uri.Builder uriBuilder = new Uri.Builder();
                        uriBuilder.authority("content://edu.buffalo.cse.cse486586.simpledynamo.provider");
                        uriBuilder.scheme("content");
                        Uri mUri = uriBuilder.build();
                        String[] splitMsg = msgReceived.split("_");
                        ContentValues mNewValues = new ContentValues();
                        //Log.i(TAG, "doInBackground: break1");
                        mNewValues.put("key", splitMsg[0]);
                        //Log.i(TAG, "doInBackground: break2");
                        mNewValues.put("value", splitMsg[1]);
                        insert(mUri, mNewValues);
                    }
                    if (msgReceived.contains("-")) {
                        Uri.Builder uriBuilder = new Uri.Builder();
                        uriBuilder.authority("content://edu.buffalo.cse.cse486586.simpledht.provider");
                        uriBuilder.scheme("content");
                        Uri mUri = uriBuilder.build();
                        String[] splitMsg = msgReceived.split("-");
                        tempNo = Integer.parseInt(splitMsg[1]);
                        query(mUri,null, "*",null, null, null);
                    }
                    if (msgReceived.contains(",")) {
                        String[] splitMsg = msgReceived.split(",");
                        if (keys.contains(splitMsg[0])) {
                            String query = splitMsg[0] + "_" + splitMsg[1];
                            Uri.Builder uriBuilder = new Uri.Builder();
                            uriBuilder.authority("content://edu.buffalo.cse.cse486586.simpledht.provider");
                            uriBuilder.scheme("content");
                            Uri mUri = uriBuilder.build();
                            query(mUri,null, query,null, null, null);
                        }
                    }
                    if (msgReceived.contains("@")) {

                        String[] splitMsg = msgReceived.split("@");
                        String query = splitMsg[0] + "~" + splitMsg[1] + "~" + splitMsg[2];
                        if (splitMsg[2].equals(meraLambaPort)) {
                            Uri.Builder uriBuilder = new Uri.Builder();
                            uriBuilder.authority("content://edu.buffalo.cse.cse486586.simpledht.provider");
                            uriBuilder.scheme("content");
                            Uri mUri = uriBuilder.build();
                            query(mUri, null, query, null, null, null);
                        }
                        else {
                            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,  msgReceived, "answer");
                        }
                    }
                    clientSocket = serverSocket.accept();
                    msgIn = new DataInputStream(clientSocket.getInputStream());
                }

            } catch (IOException e) {
                Log.i(TAG, "doInBackground: Exception in reading message\n" + e);
                try {

                    serverSocket = new ServerSocket(SERVER_PORT);
                    new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
                } catch (IOException g) {
                    Log.e(TAG, "Can't create a ServerSocket");
                }
            }

            //Log.i(TAG, "Recieved message: " + message);
            return null;
        }
    }

    /***
     * ClientTask is an AsyncTask that should send a string over the network.
     * It is created by ClientTask.executeOnExecutor() call whenever OnKeyListener.onKey() detects
     * an enter key press event.
     *
     * @author stevko
     *
     */
    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            DataOutputStream msgOut;
            try {
                if (msgs[1].equals("init")) {
                    if (!msgs[0].equals("5554")) {
                        String msgToSend;
                        msgToSend = "alive:" + msgs[0];
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(REMOTE_PORT0));
                        msgOut = new DataOutputStream(socket.getOutputStream());
                        msgOut.writeUTF(msgToSend);
                        msgOut.flush();
                        Log.i(TAG, "doInBackground: hfs msg sent: " + msgToSend);
                    }
                }
                else if (msgs[1].equals("re")) {
                    for(String portNo : portAlive) {
                        String msgToSend = msgs[0];
                        Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                (Integer.parseInt(portNo)*2));
                        msgOut = new DataOutputStream(socket0.getOutputStream());
                        msgOut.writeUTF(msgToSend);
                        msgOut.flush();
                        Log.i(TAG, "doInBackground: done msg sent: " + msgToSend + ":" + portNo);
                    }
                }
                else if (msgs[1].equals("aagebhej")) {
                    String msgToSend = msgs[0];
                    Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(aage)*2);
                    msgOut = new DataOutputStream(socket0.getOutputStream());
                    msgOut.writeUTF(msgToSend);
                    msgOut.flush();
                    Log.i(TAG, "doInBackground: yeh aage bheja hai: " + msgToSend);
                }
                else if (msgs[1].equals("gDump")) {
                    String msgToSend = msgs[0];
                    Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(aage)*2);
                    msgOut = new DataOutputStream(socket0.getOutputStream());
                    msgOut.writeUTF(msgToSend);
                    msgOut.flush();
                }
                else if (msgs[1].equals("query")) {
                    String msgToSend = msgs[0] + "," + meraLambaPort;
                    Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(aage)*2);
                    msgOut = new DataOutputStream(socket0.getOutputStream());
                    msgOut.writeUTF(msgToSend);
                    msgOut.flush();
                }
                else if (msgs[1].equals("answer")) {
                    String msgToSend = msgs[0];
                    Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(aage)*2);
                    msgOut = new DataOutputStream(socket0.getOutputStream());
                    msgOut.writeUTF(msgToSend);
                    msgOut.flush();
                }
            /*} catch (UnknownHostException e) {
                Log.e(TAG, "ClientTask UnknownHostException");*/
            } catch (Exception e) {
                Log.e(TAG, "ClientTask socket IOException:" + e);
            }

            return null;
        }
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        if (selection.equals("@") || selection.equals("*")) {
            for (int x = 0; x < keys.size(); x++) {
                try {
                    Log.i("shahyash", "query:Key = " + keys.get(x));
                    File test = new File(genHash(keys.get(x)));
                    test.delete();

                } catch (Exception e) {
                    Log.e("shahyash", "query: IOException Encountered: ", e);
                }
            }
        } else {
            try {
                File test = new File(genHash(selection));
                test.delete();
            } catch (Exception e) {
                Log.e("shahyash", "query: IOException Encountered: ", e);
            }
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {

        /*
         * TODO: You need to implement this method. Note that values will have two columns (a key
         * column and a value column) and one row that contains the actual (key, value) pair to be
         * inserted.
         *
         * For actual storage, you can use any option. If you know how to use SQL, then you can use
         * SQLite. But this is not a requirement. You can use other storage options, such as the
         * internal storage option that we used in PA1. If you want to use that option, please
         * take a look at the code for PA1.
         */
        Log.v("insert", values.toString());
        String value = (String) values.get("value");
        String key = (String) values.get("key");
        String hashedKey;

        try {
            hashedKey = genHash(key);
/*            if (aage != null) {
                Log.i(TAG, "insert: wolo: " + hashedKey.compareTo(mineHashedPort) + " : " + hashedKey.compareTo(genHash(aage)));
                Log.i(TAG, "insert: wolo2: " + genHash(aage).equals(hashedPortAlive.get(0)));
            }*/

            if(isThisTheNode(hashedKey)) {
                keys.add(key);
                FileOutputStream out;
                out = getContext().openFileOutput(hashedKey, Context.MODE_PRIVATE);
                out.write(value.getBytes());
                out.close();
                Log.i("shahyash", "insert: Key = " + key + " hashed key = " + hashedKey);
            }
            else {
                Log.i(TAG, "insert: yeh aage bheja hai: " + hashedKey);
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,  key + "_" + value, "aagebhej");
            }
        } catch (Exception e) {
            Log.e("shahyash", "insert: IOException in insert" + hashedPortAlive.size());
        }
        return null;
    }

/*    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        return false;
    }*/

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        /*
         * TODO: You need to implement this method. Note that you need to return a Cursor object
         * with the right format. If the formatting is not correct, then it is not going to work.
         *
         * If you use SQLite, whatever is returned from SQLite is a Cursor object. However, you
         * still need to be careful because the formatting might still be incorrect.
         *
         * If you use a file storage option, then it is your job to build a Cursor * object. I
         * recommend building a MatrixCursor described at:
         * http://developer.android.com/reference/android/database/MatrixCursor.html
         */
        Log.v("query", selection);
        char count;
        String columnNames[] = {"key", "value"};
        MatrixCursor mCursor = new MatrixCursor(columnNames);
        StringBuilder stringBuilder = new StringBuilder();
        FileInputStream fileInputStream;

        if (selection.equals("@") || selection.equals("*")) {
            if (selection.equals("*")) {
                int size = hashedPortAlive.size();
                tempNo = tempNo - 1;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,  "*-" + tempNo, "gDump");
                tempNo = hashedPortAlive.size();
            }
            for (int x = 0; x < keys.size(); x++) {
                stringBuilder = new StringBuilder();
                try {
                    Log.i("shahyash", "query:Key = " + keys.get(x));
                    fileInputStream = getContext().openFileInput(genHash(keys.get(x)));
                    for (int i; (i = fileInputStream.read()) != -1; ) {
                        count = (char) i;
                        stringBuilder.append(count);
                    }
                } catch (Exception e) {
                    Log.e("shahyash", "query: IOException Encountered: ", e);
                }

                String value = stringBuilder.toString();
                String row[] = {keys.get(x), value};
                mCursor.addRow(row);
            }
        } else {
            if (selection.contains("_")) {
                String[] splitMsg = selection.split("_");
                try {
                    fileInputStream = getContext().openFileInput(genHash(splitMsg[0]));
                    for (int i; (i = fileInputStream.read()) != -1; ) {
                        count = (char) i;
                        stringBuilder.append(count);
                    }
                } catch (Exception e) {
                    Log.e("shahyash", "query: IOException Encountered: ", e);
                }
                String answer = splitMsg[0] + "@" + stringBuilder.toString() + "@" + splitMsg[1];
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,  answer, "answer");
            }
            else if (selection.contains("~")) {
                String[] splitMsg = selection.split("~");
                String value = splitMsg[1];
                String row[] = {splitMsg[0], value};
                mCursor.addRow(row);
            }
            else if (keys.contains(selection)) {
                try {
                    fileInputStream = getContext().openFileInput(genHash(selection));
                    for (int i; (i = fileInputStream.read()) != -1; ) {
                        count = (char) i;
                        stringBuilder.append(count);
                    }
                    String value = stringBuilder.toString();
                    String row[] = {selection, value};
                    mCursor.addRow(row);
                } catch (Exception e) {
                    Log.e("shahyash", "query: IOException Encountered: ", e);
                }
            } else {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,  selection, "query");
                try {
                    throw new IOException();
                }
                catch (IOException e) {
                    Log.i(TAG, "query: bc");
                }
            }
        }
        Log.i(TAG, "query: " + DatabaseUtils.dumpCursorToString(mCursor));
        return mCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}