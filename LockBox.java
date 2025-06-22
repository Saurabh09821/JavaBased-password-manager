import java.awt.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.sql.*;
import java.security.SecureRandom;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

// Linear Probing Implementation
class HashtablePassword implements hashTableMap {
    private final int useProbe;    // 0 = Linear Probing, 1 = Quadratic Probing
    private Entry[] entries;       // The array of entries
    private final float loadFactor;     // The load factor
    private int size, used;         // used acquires space for NIL
    private final Entry NIL = new Entry(null, null); // Deleted entries

    private static class Entry {
        Object key, value;
        Entry(Object k, Object v) {
            key = k; value = v;
        }
    }

    public HashtablePassword(int capacity, float loadFactor, int useProbe) {
        entries = new Entry[capacity];
        this.loadFactor = loadFactor;
        this.useProbe = useProbe;
    }

    // Complementary functions
    public int hash(Object key) {
        return (key.hashCode() & 0x7FFFFFFF) % entries.length;
    }

    private int nextProbe(int h, int i) {
        return (h + i) % entries.length;  // Linear Probing
    }

    private void rehash() {
        Entry[] oldEntries = entries;
        entries = new Entry[2 * entries.length + 1];
        for (Entry entry : oldEntries) {
            if (entry == NIL || entry == null) continue;
            int h = hash(entry.key);
            for (int x = 0; x < entries.length; x++) {
                int j = nextProbe(h, x);
                if (entries[j] == null) {
                    entries[j] = entry;
                    break;
                }
            }
            used = size;
        }
    }

    @Override
    public int add_Acc(Object Account, Object passwd) {
        if (used > (loadFactor * entries.length)) rehash();
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = (h + i) % entries.length;
            Entry entry = entries[j];
            if (entry == null) {
                entries[j] = new Entry(Account, passwd);
                ++size;
                ++used;
                return h;
            }
            if (entry == NIL) continue;
            if (entry.key.equals(Account)) {
                Object oldValue = entry.value;
                entries[j].value = passwd;
                return (int) oldValue;
            }
        }
        return h;
    }

    @Override
    public Object get_Acc(Object Account) {
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = nextProbe(h, i);
            Entry entry = entries[j];
            if (entry == null) break;
            if (entry == NIL) continue;
            if (entry.key.equals(Account)) return entry.value;
        }
        return null;
    }

    @Override
    public Object remove_Acc(Object Account) {
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = nextProbe(h, i);
            Entry entry = entries[j];
            if (entry == NIL) continue;
            if (entry.key.equals(Account)) {
                Object Value = entry.value;
                entries[j] = NIL;
                size--;
                return Value;
            }
        }
        return null;
    }
}

// 2. CryptoUtil Class
class CryptoUtil {
    Cipher ecipher;
    Cipher dcipher;

    // 8-byte Salt
    byte[] salt = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
    };

    // Iteration count
    int iterationCount = 19;

    public CryptoUtil() {
    }

    /**
     * @param secretKey Key used to encrypt data
     * @param plainText Text input to be encrypted
     * @return Returns encrypted text
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String encrypt(String secretKey, String plainText)
            throws NoSuchAlgorithmException,
                   InvalidKeySpecException,
                   NoSuchPaddingException,
                   InvalidKeyException,
                   InvalidAlgorithmParameterException,
                   UnsupportedEncodingException,
                   IllegalBlockSizeException,
                   BadPaddingException {

        // Key generation for encryption
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);

        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

        // Encryption process
        ecipher = Cipher.getInstance(key.getAlgorithm());
        ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        String charSet = "UTF-8";
        byte[] in = plainText.getBytes(charSet);
        byte[] out = ecipher.doFinal(in);
        return new String(Base64.getEncoder().encode(out));
    }

    /**
     * @param secretKey Key used to decrypt data
     * @param encryptedText encrypted text input to decrypt
     * @return Returns plain text after decryption
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String decrypt(String secretKey, String encryptedText)
            throws NoSuchAlgorithmException,
                   InvalidKeySpecException,
                   NoSuchPaddingException,
                   InvalidKeyException,
                   InvalidAlgorithmParameterException,
                   UnsupportedEncodingException,
                   IllegalBlockSizeException,
                   BadPaddingException,
                   IOException {

        // Key generation for decryption
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);

        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

        // Decryption process
        dcipher = Cipher.getInstance(key.getAlgorithm());
        dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        byte[] enc = Base64.getDecoder().decode(encryptedText);
        byte[] utf8 = dcipher.doFinal(enc);

        String charSet = "UTF-8";
        return new String(utf8, charSet);
    }
}
// 3. PasswordGenerator Class
class PasswordGenerator {
    private static final SecureRandom random = new SecureRandom();
    private static final String caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String small_caps = "abcdefghijklmnopqrstuvwxyz";
    private static final String Numeric = "1234567890";
    private static final String special_char = "~!@#$%^&*(+{}|:[?]>=<";
    private static final String dic = caps + small_caps + Numeric + special_char;

    public String generatePassword(int len) {
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < len; i++) {
            int index = random.nextInt(dic.length());
            password.append(dic.charAt(index));
        }
        return password.toString();
    }
}


// 4. hashTableMap Interface
interface hashTableMap {
    Object get_Acc(Object Account);
    int add_Acc(Object Account, Object passwd);
    Object remove_Acc(Object Account);
}

// 5. LockBox GUI Class
class LockBox implements ActionListener {
    // GUI components, database connection, and event logic
    private Connection connection; // MySQL database connection

    // Store password class reference
    HashtablePassword data = new HashtablePassword(15, 0.5F, 0);

    // GUI variables declaration
    JFrame frame;
    JFrame frame2;
    JLabel background;
    Container conn1, conn2;
    JLabel lAcc, lPass;
    JTextArea encryptPasswdArea, genePassArea, searchPassArea;
    JButton PassGeneBtn, PassEncryptBtn, PassStoreBtn, PassSearchBtn, AccAddBtn, PassDeleteBtn;
    JTextField tAcc, tPass;
    JFrame conn3;

    @Override
    public void actionPerformed(ActionEvent e) {
    }

    // Frame settings
    public static void FrameGUI(JFrame frame) {
        frame.setVisible(true);
        frame.setLayout(null);
        frame.setLocationRelativeTo(null);
    }

    // Container settings
    public static void ContainerGUI(Container conn) {
        conn.setVisible(true);
        conn.setBackground(new Color(0xBEBEFF));
        conn.setLayout(null);
    }

    // Buttons settings
    public void GUIButtonsSetting(JButton btn) {
        btn.setBackground(new Color(0X190482));
        btn.setForeground(new Color(0X8E8FFA));
        btn.setBorder(BorderFactory.createLineBorder(new Color(0X7752FE), 3));
        btn.setFocusable(false);
        Cursor crs = new Cursor(Cursor.HAND_CURSOR);
        btn.setCursor(crs);
        Font fn = new Font("Bernard MT Condensed", Font.PLAIN, 20);
        btn.setFont(fn);
    }

    // GUI of Store password
    public void StoringGUI() {
        frame2 = new JFrame("Store your passwords");
        frame2.setBounds(1400, 300, 800, 500);
        frame2.setSize(400, 400);
        FrameGUI(frame2);
        conn2 = frame2.getContentPane();
        ContainerGUI(conn2);
        Font fn = new Font("Book Antiqua", Font.BOLD, 20);

        // Account textField and label
        lAcc = new JLabel("ACCOUNT NAME");
        lAcc.setBounds(90, 23, 380, 20);
        lAcc.setFont(fn);
        conn2.add(lAcc);

        tAcc = new JTextField();
        tAcc.setBounds(90, 70, 200, 50);
        tAcc.setFont(fn);
        tAcc.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tAcc.setForeground(Color.DARK_GRAY);
        conn2.add(tAcc);

        // Account password textField and label
        lPass = new JLabel("ACCOUNT PASSWORD");
        lPass.setBounds(90, 160, 380, 20);
        lPass.setFont(fn);
        conn2.add(lPass);

        tPass = new JTextField();
        tPass.setBounds(90, 200, 200, 50);
        tPass.setFont(fn);
        tPass.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tPass.setForeground(Color.DARK_GRAY);
        conn2.add(tPass);

        AccAddBtn = new JButton("STORE");
        AccAddBtn.setBounds(120, 290, 150, 50);
        conn2.add(AccAddBtn);
        GUIButtonsSetting(AccAddBtn);
    }

    // For password generator and encryption
    public void textArea(String Pass, JTextArea TA) {
        TA.setText(Pass);
        Font fn = new Font("Book Antiqua", Font.BOLD, 20);
        TA.setWrapStyleWord(true);
        TA.setLineWrap(true);
        TA.setCaretPosition(0);
        TA.setEditable(false);
        TA.setFont(fn);
    }

    // Create a MySQL connection
    private void connectToDatabase() {
        try {
            String url = "jdbc:mysql://localhost:3306/password_manager_db";
            String username = "root";
            String password = "@Hxccfddondfdfey0gfgf7";
            connection = DriverManager.getConnection(url, username, password);

            // Create a table to store passwords if it doesn't exist
            createPasswordTable();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Create table to store passwords
    private void createPasswordTable() {
        try {
            Statement statement = connection.createStatement();
            String createTableSQL = "CREATE TABLE IF NOT EXISTS passwords (" +
                                    "account_name VARCHAR(255) NOT NULL PRIMARY KEY," +
                                    "password VARCHAR(255) NOT NULL)";
            statement.executeUpdate(createTableSQL);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Store password in MySQL database
    private void storePasswordInDatabase(String accountName, String password) {
        try {
            String insertSQL = "INSERT INTO passwords (account_name, password) VALUES (?, ?)";
            PreparedStatement preparedStatement = connection.prepareStatement(insertSQL);
            preparedStatement.setString(1, accountName);
            preparedStatement.setString(2, password);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Search password in mysql databse
    private String searchPasswordInDatabase(String accountName) {
        try {
            String selectSQL = "SELECT password FROM passwords WHERE account_name = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(selectSQL);
            preparedStatement.setString(1, accountName);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("password");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Delete password from my sql databse
    private void deletePasswordFromDatabase(String accountName) {
        try {
            String deleteSQL = "DELETE FROM passwords WHERE account_name = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(deleteSQL);
            preparedStatement.setString(1, accountName);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // GUI of LockBox
    public LockBox() {
        // Initialize the database connection
        connectToDatabase();

        frame = new JFrame("LockBox");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 650);
        frame.setResizable(false);
        ImageIcon img = new ImageIcon("background.png");
        background = new JLabel("", img, JLabel.CENTER);
        background.setBounds(0, 0, 400, 650);
        background.setVisible(true);
        frame.add(background);

        FrameGUI(frame);
        conn1 = frame.getContentPane();
        ContainerGUI(conn1);

        // Password generator button
        PassGeneBtn = new JButton("GENERATE PASSWORD");
        PassGeneBtn.setBounds(90, 20, 220, 40);
        conn1.add(PassGeneBtn);
        GUIButtonsSetting(PassGeneBtn);

        //generating password
        PassGeneBtn.addActionListener(e -> {
            if (PassGeneBtn == e.getSource()) {
                try {
                    int len = Integer.parseInt(JOptionPane.showInputDialog("Enter the password length"));
                    if (len > 4) {
                        //password generator class reference
                        PasswordGenerator pass = new PasswordGenerator();
                        String passwd = pass.generatePassword(len);
                        genePassArea = new JTextArea(5, 4);
                        textArea(passwd, genePassArea);
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Copy your password", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(conn1, "Password length must be greater than 8!", "Invalid Input Error", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Encryption button
        JButton EncryptBtn = new JButton("ENCRYPT Text");
        EncryptBtn.setBounds(90, 90, 220, 40);
        conn1.add(EncryptBtn);
        GUIButtonsSetting(EncryptBtn);
        EncryptBtn.addActionListener(e -> {
            if (EncryptBtn == e.getSource()) {
                try {
                    String text = JOptionPane.showInputDialog("Enter the text to encrypt");
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key");
                    if (text.length() > 0 && secretKey.length() > 0) {
                        //password generator class refernce
                        CryptoUtil pass1 = new CryptoUtil();
                        String passwd = pass1.encrypt(secretKey, text);
                        genePassArea = new JTextArea(5, 4);
                        textArea(passwd, genePassArea);
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Copy your password", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(conn1, "Write something", "Invalid Input Error", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Decryption button
        JButton DecryptBtn = new JButton("DECRYPT Text");
        DecryptBtn.setBounds(90, 160, 220, 40);
        conn1.add(DecryptBtn);
        GUIButtonsSetting(DecryptBtn);
        DecryptBtn.addActionListener(e -> {
            if (DecryptBtn == e.getSource()) {
                try {
                    String text = JOptionPane.showInputDialog("Enter the text to decrypt");//getting the encrypted text
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key");//getting the secret key
                    if (text.length() > 0 && secretKey.length() > 0) {
                        CryptoUtil pass1 = new CryptoUtil();
                        String passwd = pass1.decrypt(secretKey, text);
                        genePassArea = new JTextArea(5, 4);
                        textArea(passwd, genePassArea);
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Decrypted text", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(conn1, "Password length must be greater than 8!", "Invalid Input Error", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Store password
        PassStoreBtn = new JButton("STORE PASSWORD");
        PassStoreBtn.setBounds(90, 230, 220, 40);
        conn1.add(PassStoreBtn);
        GUIButtonsSetting(PassStoreBtn);
        PassStoreBtn.addActionListener(e -> {
            if (PassStoreBtn == e.getSource()) {
                try {
                    StoringGUI();
                    AccAddBtn.addActionListener(e4 -> {
                        if (AccAddBtn == e4.getSource()) {
                            String account_name = tAcc.getText();
                            String acc_pass = tPass.getText();
                            if (account_name.isEmpty() && acc_pass.isEmpty()) {
                                JOptionPane.showMessageDialog(conn2, "unable to store your password!", "ERROR", JOptionPane.ERROR_MESSAGE);
                            } else {
                                storePasswordInDatabase(account_name, acc_pass);
                                JOptionPane.showMessageDialog(conn2, "Account added Successfully !");
                                tAcc.setText(null);
                                tPass.setText(null);
                            }
                        }
                    });
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn2, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Search password
        PassSearchBtn = new JButton("SEARCH PASSWORD");
        GUIButtonsSetting(PassSearchBtn);
        PassSearchBtn.setBounds(90, 300, 220, 40);
        conn1.add(PassSearchBtn);
        PassSearchBtn.addActionListener(e -> {
            if (PassSearchBtn == e.getSource()) {
                try {
                    String acc_name = JOptionPane.showInputDialog("Enter your Account Name");
                    if (!acc_name.isBlank()) {
                        Object pass = searchPasswordInDatabase(acc_name.toLowerCase());
                        if (pass != null) {
                            searchPassArea = new JTextArea(4, 5);
                            textArea(String.valueOf(pass), searchPassArea);
                            JOptionPane.showMessageDialog(conn1, new JScrollPane(searchPassArea), "Copy your password", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            JOptionPane.showMessageDialog(conn1, "Account not Found!");
                        }
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Delete password
        PassDeleteBtn = new JButton("DELETE PASSWORD");
        GUIButtonsSetting(PassDeleteBtn);
        PassDeleteBtn.setBounds(90, 370, 220, 40);
        conn1.add(PassDeleteBtn);
        PassDeleteBtn.addActionListener(e -> {
            if (PassDeleteBtn == e.getSource()) {
                try {
                    String acc_name = JOptionPane.showInputDialog("Enter the Account Name");
                    if (!acc_name.isBlank()) {
                        deletePasswordFromDatabase(acc_name.toLowerCase());
                        JOptionPane.showMessageDialog(conn1, "Delete successfully!");
                    } else {
                        JOptionPane.showMessageDialog(conn1, "Account not found!", "INFO", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }

    // main method to run the application    
    public static void main(String[] args) {
        try {
            new LockBox();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
