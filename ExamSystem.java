import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Online Examination System - Java Swing.
 * Demo logins: student1 / pass123   student2 / pass456
 * Screens (CardLayout): Login -> Profile -> Exam -> Result -> (Logout) -> Login
 *
 * Tip: run with  java -Dexam.seconds=20 ExamSystem  to test the auto-submit quickly.
 */
public class ExamSystem extends JFrame {

    static final int EXAM_SECONDS = Integer.getInteger("exam.seconds", 30 * 60);
    static final Font BASE = new Font(Font.SANS_SERIF, Font.PLAIN, 15);
    static final Font BOLD = BASE.deriveFont(Font.BOLD);

    // ------------------------------------------------------------------ model
    record Question(String text, String[] options, int correct) {}

    static List<Question> questionBank() {
        List<Question> q = new ArrayList<>();
        q.add(new Question("Which keyword is used to inherit a class in Java?",
                new String[]{"implements", "extends", "inherits", "super"}, 1));
        q.add(new Question("What is the default value of an int instance variable in Java?",
                new String[]{"null", "undefined", "0", "-1"}, 2));
        q.add(new Question("Which collection does NOT allow duplicate elements?",
                new String[]{"ArrayList", "LinkedList", "Vector", "HashSet"}, 3));
        q.add(new Question("Which of these is NOT a primitive data type in Java?",
                new String[]{"boolean", "String", "char", "double"}, 1));
        q.add(new Question("Which method is the entry point of a Java application?",
                new String[]{"start()", "run()", "main()", "init()"}, 2));
        q.add(new Question("What does the 'final' keyword do when applied to a variable?",
                new String[]{"Makes it static", "Prevents reassignment", "Makes it private", "Makes it thread-safe"}, 1));
        q.add(new Question("Which interface must a class implement to be used with a for-each loop?",
                new String[]{"Iterable", "Comparable", "Runnable", "Cloneable"}, 0));
        q.add(new Question("Which exception is thrown when dividing an integer by zero?",
                new String[]{"NullPointerException", "ArithmeticException", "NumberFormatException", "IOException"}, 1));
        q.add(new Question("Which JDBC interface is used to prevent SQL injection?",
                new String[]{"Statement", "Connection", "PreparedStatement", "ResultSet"}, 2));
        q.add(new Question("Which Swing class is used to run code periodically on the Event Dispatch Thread?",
                new String[]{"java.util.Timer", "javax.swing.Timer", "Thread", "ScheduledFuture"}, 1));
        return q;
    }

    // ------------------------------------------------------------- user store
    /** Users persisted in users.txt (tab-separated: username, display name, salt:hash). */
    static final class UserStore {
        record User(String username, String displayName, String hash) {}

        private static final Path FILE = Paths.get("users.txt");
        private static final SecureRandom RNG = new SecureRandom();
        private static final Map<String, User> USERS = new LinkedHashMap<>();

        static void load() throws IOException {
            USERS.clear();
            if (!Files.exists(FILE)) {
                USERS.put("student1", new User("student1", "Student One", hash("pass123".toCharArray())));
                USERS.put("student2", new User("student2", "Student Two", hash("pass456".toCharArray())));
                save();
                return;
            }
            for (String line : Files.readAllLines(FILE, StandardCharsets.UTF_8)) {
                String[] p = line.split("\t", -1);
                if (p.length == 3) USERS.put(p[0], new User(p[0], p[1], p[2]));
            }
        }

        private static void save() throws IOException {
            List<String> lines = new ArrayList<>();
            for (User u : USERS.values()) lines.add(u.username() + "\t" + u.displayName() + "\t" + u.hash());
            Files.write(FILE, lines, StandardCharsets.UTF_8);
        }

        static User authenticate(String username, char[] pw) {
            User u = USERS.get(username);
            if (u == null) return null;
            String[] parts = u.hash().split(":");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] expected = Base64.getDecoder().decode(parts[1]);
            return MessageDigest.isEqual(expected, pbkdf2(pw, salt)) ? u : null;
        }

        /** Updates display name and (if newPassword != null) the password. Returns the updated user. */
        static User update(String username, String displayName, char[] newPassword) throws IOException {
            User old = USERS.get(username);
            User updated = new User(username, displayName,
                    newPassword == null ? old.hash() : hash(newPassword));
            USERS.put(username, updated);
            save();
            return updated;
        }

        private static String hash(char[] pw) {
            byte[] salt = new byte[16];
            RNG.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt) + ":" +
                    Base64.getEncoder().encodeToString(pbkdf2(pw, salt));
        }

        private static byte[] pbkdf2(char[] pw, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(pw, salt, 65536, 256);
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            } catch (java.security.NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ------------------------------------------------------------ frame/cards
    private static final String LOGIN = "login", PROFILE = "profile", EXAM = "exam", RESULT = "result";

    private final CardLayout cards = new CardLayout();
    private final JPanel root = new JPanel(cards);
    private final LoginPanel loginPanel = new LoginPanel();
    private final ProfilePanel profilePanel = new ProfilePanel();
    private final ExamPanel examPanel = new ExamPanel();
    private final ResultPanel resultPanel = new ResultPanel();
    private UserStore.User currentUser;

    ExamSystem() {
        super("Online Examination System");
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        root.add(loginPanel, LOGIN);
        root.add(profilePanel, PROFILE);
        root.add(examPanel, EXAM);
        root.add(resultPanel, RESULT);
        setContentPane(root);
        setSize(760, 560);
        setLocationRelativeTo(null);

        // Session management: closing mid-exam must be confirmed.
        addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) {
                if (examPanel.inProgress) {
                    if (examPanel.confirm("Are you sure you want to quit?\nYour exam will NOT be submitted.",
                            "Quit Exam")) {
                        System.exit(0);
                    }
                } else {
                    System.exit(0);
                }
            }
        });
        showLogin();
    }

    void showLogin() {
        currentUser = null;
        loginPanel.reset();
        cards.show(root, LOGIN);
        getRootPane().setDefaultButton(loginPanel.loginButton);
    }

    void showProfile() {
        profilePanel.load(currentUser);
        cards.show(root, PROFILE);
        getRootPane().setDefaultButton(null);
    }

    void startExam() {
        cards.show(root, EXAM);
        getRootPane().setDefaultButton(null);
        examPanel.start(currentUser);
    }

    void showResult(List<Question> qs, int[] answers, long secondsTaken) {
        resultPanel.display(currentUser, qs, answers, secondsTaken);
        cards.show(root, RESULT);
    }

    static String mmss(long secs) {
        return String.format("%02d:%02d", secs / 60, secs % 60);
    }

    static JLabel label(String text, Font f) {
        JLabel l = new JLabel(text);
        l.setFont(f);
        return l;
    }

    // ------------------------------------------------------------ login panel
    class LoginPanel extends JPanel {
        final JTextField userField = new JTextField(16);
        final JPasswordField passField = new JPasswordField(16);
        final JButton loginButton = new JButton("Login");

        LoginPanel() {
            setLayout(new GridBagLayout());
            JPanel box = new JPanel(new GridBagLayout());
            box.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Color.LIGHT_GRAY),
                    BorderFactory.createEmptyBorder(25, 35, 25, 35)));
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(8, 6, 8, 6);
            g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
            box.add(label("Online Examination System", BASE.deriveFont(Font.BOLD, 22f)), g);
            g.gridwidth = 1; g.anchor = GridBagConstraints.WEST;
            g.gridy = 1; g.gridx = 0; box.add(label("Username:", BASE), g);
            g.gridx = 1; box.add(userField, g);
            g.gridy = 2; g.gridx = 0; box.add(label("Password:", BASE), g);
            g.gridx = 1; box.add(passField, g);
            g.gridy = 3; g.gridx = 1; g.anchor = GridBagConstraints.EAST; box.add(loginButton, g);
            add(box);
            loginButton.addActionListener(e -> doLogin());
        }

        void reset() {
            userField.setText("");
            passField.setText("");
            userField.requestFocusInWindow();
        }

        private void doLogin() {
            String user = userField.getText().trim();
            char[] pw = passField.getPassword();
            try {
                if (user.isEmpty() || pw.length == 0) {
                    JOptionPane.showMessageDialog(this, "Please enter username and password.",
                            "Login", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                UserStore.User u = UserStore.authenticate(user, pw);
                if (u == null) {
                    JOptionPane.showMessageDialog(this, "Invalid username or password.",
                            "Login Failed", JOptionPane.ERROR_MESSAGE);
                    passField.setText("");
                } else {
                    currentUser = u;
                    showProfile();
                }
            } finally {
                java.util.Arrays.fill(pw, '\0');
            }
        }
    }

    // ---------------------------------------------------------- profile panel
    class ProfilePanel extends JPanel {
        private final JLabel welcome = label("", BASE.deriveFont(Font.BOLD, 20f));
        private final JLabel userLabel = label("", BASE);
        private final JTextField nameField = new JTextField(20);
        private final JPasswordField newPass = new JPasswordField(20);
        private final JPasswordField confirmPass = new JPasswordField(20);

        ProfilePanel() {
            setLayout(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(20, 40, 20, 40));
            add(welcome, BorderLayout.NORTH);

            JPanel form = new JPanel(new GridBagLayout());
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(8, 6, 8, 6);
            g.anchor = GridBagConstraints.WEST;
            g.gridy = 0; g.gridx = 0; form.add(label("Username:", BASE), g);
            g.gridx = 1; form.add(userLabel, g);
            g.gridy = 1; g.gridx = 0; form.add(label("Display name:", BASE), g);
            g.gridx = 1; form.add(nameField, g);
            g.gridy = 2; g.gridx = 0; form.add(label("New password:", BASE), g);
            g.gridx = 1; form.add(newPass, g);
            g.gridy = 3; g.gridx = 0; form.add(label("Confirm password:", BASE), g);
            g.gridx = 1; form.add(confirmPass, g);
            g.gridy = 4; g.gridx = 1;
            JLabel hint = label("Leave the password fields blank to keep your current password.", BASE.deriveFont(12f));
            hint.setForeground(Color.GRAY);
            form.add(hint, g);
            JButton save = new JButton("Save Changes");
            g.gridy = 5; form.add(save, g);
            add(form, BorderLayout.CENTER);

            JButton logout = new JButton("Logout");
            JButton start = new JButton("Start Exam");
            start.setFont(BOLD);
            JPanel south = new JPanel(new BorderLayout());
            JLabel info = label("<html>" + questionBank().size() + " questions &nbsp;|&nbsp; Time limit: "
                    + mmss(EXAM_SECONDS) + " (mm:ss) &nbsp;|&nbsp; The exam is auto-submitted when time runs out.</html>",
                    BASE.deriveFont(13f));
            south.add(info, BorderLayout.NORTH);
            JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            btns.add(logout);
            btns.add(start);
            south.add(btns, BorderLayout.SOUTH);
            add(south, BorderLayout.SOUTH);

            save.addActionListener(e -> save());
            logout.addActionListener(e -> showLogin());
            start.addActionListener(e -> startExam());
        }

        void load(UserStore.User u) {
            welcome.setText("Welcome, " + u.displayName());
            userLabel.setText(u.username());
            nameField.setText(u.displayName());
            newPass.setText("");
            confirmPass.setText("");
        }

        private void save() {
            String name = nameField.getText().trim().replace("\t", " ");
            char[] p1 = newPass.getPassword();
            char[] p2 = confirmPass.getPassword();
            try {
                if (name.isEmpty()) { warn("Display name cannot be empty."); return; }
                char[] newPw = null;
                if (p1.length > 0 || p2.length > 0) {
                    if (!java.util.Arrays.equals(p1, p2)) { warn("Passwords do not match."); return; }
                    if (p1.length < 6) { warn("Password must be at least 6 characters."); return; }
                    newPw = p1;
                }
                currentUser = UserStore.update(currentUser.username(), name, newPw);
                load(currentUser);
                JOptionPane.showMessageDialog(this, "Profile updated successfully.",
                        "Profile", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Could not save profile: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            } finally {
                java.util.Arrays.fill(p1, '\0');
                java.util.Arrays.fill(p2, '\0');
            }
        }

        private void warn(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Profile", JOptionPane.WARNING_MESSAGE);
        }
    }

    // ------------------------------------------------------------- exam panel
    class ExamPanel extends JPanel {
        boolean inProgress = false;

        private List<Question> questions;
        private int[] answers;
        private int index;
        private long startNanos;
        private final long limitNanos = EXAM_SECONDS * 1_000_000_000L;
        private final javax.swing.Timer timer = new javax.swing.Timer(250, e -> tick());
        private JDialog openDialog; // so an auto-submit can close a pending confirmation

        private final JLabel candidateLabel = label("", BASE);
        private final JLabel counterLabel = label("", BOLD);
        private final JLabel timerLabel = label("", BASE.deriveFont(Font.BOLD, 22f));
        private final JTextArea questionArea = new JTextArea(3, 40);
        private final JRadioButton[] options = new JRadioButton[4];
        private final ButtonGroup group = new ButtonGroup();
        private final JButton prevBtn = new JButton("< Previous");
        private final JButton nextBtn = new JButton("Next >");
        private final JButton submitBtn = new JButton("Submit Exam");

        ExamPanel() {
            setLayout(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(15, 25, 15, 25));

            JPanel header = new JPanel(new BorderLayout());
            JPanel left = new JPanel(new GridLayout(2, 1));
            left.add(candidateLabel);
            left.add(counterLabel);
            header.add(left, BorderLayout.WEST);
            JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            right.add(label("Time left: ", BASE));
            right.add(timerLabel);
            header.add(right, BorderLayout.EAST);
            header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));
            add(header, BorderLayout.NORTH);

            questionArea.setEditable(false);
            questionArea.setLineWrap(true);
            questionArea.setWrapStyleWord(true);
            questionArea.setOpaque(false);
            questionArea.setFont(BASE.deriveFont(Font.BOLD, 17f));
            JPanel center = new JPanel();
            center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
            center.add(questionArea);
            center.add(Box.createVerticalStrut(15));
            for (int i = 0; i < 4; i++) {
                options[i] = new JRadioButton();
                options[i].setFont(BASE.deriveFont(16f));
                group.add(options[i]);
                center.add(options[i]);
                center.add(Box.createVerticalStrut(8));
            }
            add(center, BorderLayout.CENTER);

            JPanel south = new JPanel(new BorderLayout());
            JPanel nav = new JPanel(new FlowLayout(FlowLayout.LEFT));
            nav.add(prevBtn);
            nav.add(nextBtn);
            south.add(nav, BorderLayout.WEST);
            south.add(submitBtn, BorderLayout.EAST);
            add(south, BorderLayout.SOUTH);

            prevBtn.addActionListener(e -> go(index - 1));
            nextBtn.addActionListener(e -> go(index + 1));
            submitBtn.addActionListener(e -> manualSubmit());
        }

        void start(UserStore.User user) {
            questions = questionBank();
            answers = new int[questions.size()];
            java.util.Arrays.fill(answers, -1);
            candidateLabel.setText("Candidate: " + user.displayName());
            index = 0;
            inProgress = true;
            showQuestion();
            startNanos = System.nanoTime();
            updateTimerLabel(limitNanos);
            timer.start();
        }

        private void saveCurrent() {
            answers[index] = -1;
            for (int i = 0; i < 4; i++) if (options[i].isSelected()) answers[index] = i;
        }

        private void go(int target) {
            if (!inProgress || target < 0 || target >= questions.size()) return;
            saveCurrent();
            index = target;
            showQuestion();
        }

        private void showQuestion() {
            Question q = questions.get(index);
            counterLabel.setText("Question " + (index + 1) + " of " + questions.size());
            questionArea.setText(q.text());
            group.clearSelection();
            for (int i = 0; i < 4; i++) options[i].setText((char) ('A' + i) + ".  " + q.options()[i]);
            if (answers[index] >= 0) options[answers[index]].setSelected(true);
            prevBtn.setEnabled(index > 0);
            nextBtn.setEnabled(index < questions.size() - 1);
        }

        private void tick() {
            long remaining = limitNanos - (System.nanoTime() - startNanos);
            if (remaining <= 0) {
                updateTimerLabel(0);
                finish(true);
            } else {
                updateTimerLabel(remaining);
            }
        }

        private void updateTimerLabel(long nanos) {
            long secs = (nanos + 999_999_999L) / 1_000_000_000L; // round up so 00:00 only at the very end
            timerLabel.setText(mmss(secs));
            timerLabel.setForeground(secs <= 300 ? Color.RED : Color.BLACK);
        }

        private void manualSubmit() {
            saveCurrent();
            int unanswered = 0;
            for (int a : answers) if (a < 0) unanswered++;
            String msg = unanswered > 0
                    ? "You have " + unanswered + " unanswered question(s).\nSubmit the exam anyway?"
                    : "Are you sure you want to submit the exam?";
            if (confirm(msg, "Submit Exam") && inProgress) finish(false);
        }

        /** Modal Yes/No dialog that can be closed programmatically if the timer expires meanwhile. */
        boolean confirm(String msg, String title) {
            JOptionPane pane = new JOptionPane(msg, JOptionPane.QUESTION_MESSAGE, JOptionPane.YES_NO_OPTION);
            JDialog d = pane.createDialog(ExamSystem.this, title);
            openDialog = d;
            d.setVisible(true);
            openDialog = null;
            d.dispose();
            return pane.getValue() instanceof Integer v && v == JOptionPane.YES_OPTION;
        }

        private void finish(boolean auto) {
            if (!inProgress) return;
            saveCurrent();
            timer.stop();
            inProgress = false;
            if (openDialog != null) openDialog.dispose();
            long elapsedNanos = Math.min(System.nanoTime() - startNanos, limitNanos);
            showResult(questions, answers, elapsedNanos / 1_000_000_000L);
            if (auto) {
                JOptionPane.showMessageDialog(ExamSystem.this,
                        "Time is up! Your exam has been submitted automatically.",
                        "Time Up", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    // ----------------------------------------------------------- result panel
    class ResultPanel extends JPanel {
        private final JLabel scoreLabel = label("", BASE.deriveFont(Font.BOLD, 26f));
        private final JLabel summaryLabel = label("", BASE);
        private final DefaultTableModel model = new DefaultTableModel(
                new String[]{"#", "Question", "Your Answer", "Correct Answer", "Result"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        ResultPanel() {
            setLayout(new BorderLayout(10, 10));
            setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

            JPanel top = new JPanel(new GridLayout(2, 1, 0, 6));
            top.add(scoreLabel);
            top.add(summaryLabel);
            add(top, BorderLayout.NORTH);

            JTable table = new JTable(model);
            table.setRowHeight(24);
            table.setFont(BASE.deriveFont(13f));
            table.getColumnModel().getColumn(0).setMaxWidth(35);
            table.getColumnModel().getColumn(1).setPreferredWidth(300);
            table.getColumnModel().getColumn(4).setMaxWidth(90);
            add(new JScrollPane(table), BorderLayout.CENTER);

            JButton logout = new JButton("Logout");
            logout.setFont(BOLD);
            logout.addActionListener(e -> showLogin());
            JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            south.add(logout);
            add(south, BorderLayout.SOUTH);
        }

        void display(UserStore.User user, List<Question> qs, int[] answers, long secondsTaken) {
            int correct = 0, incorrect = 0, unanswered = 0;
            model.setRowCount(0);
            for (int i = 0; i < qs.size(); i++) {
                Question q = qs.get(i);
                String yours, status;
                if (answers[i] < 0) { yours = "-"; status = "Skipped"; unanswered++; }
                else {
                    yours = (char) ('A' + answers[i]) + ". " + q.options()[answers[i]];
                    if (answers[i] == q.correct()) { status = "Correct"; correct++; }
                    else { status = "Wrong"; incorrect++; }
                }
                model.addRow(new Object[]{i + 1, q.text(), yours,
                        (char) ('A' + q.correct()) + ". " + q.options()[q.correct()], status});
            }
            int total = qs.size();
            scoreLabel.setText(user.displayName() + ": " + correct + " out of " + total
                    + " (" + Math.round(100.0 * correct / total) + "%)");
            summaryLabel.setText("Correct: " + correct + "   |   Incorrect: " + incorrect
                    + "   |   Unanswered: " + unanswered + "   |   Time taken: " + mmss(secondsTaken));
        }
    }

    // ------------------------------------------------------------------- main
    public static void main(String[] args) {
        try {
            UserStore.load();
        } catch (IOException e) {
            System.err.println("Could not load users: " + e.getMessage());
            System.exit(1);
        }
        SwingUtilities.invokeLater(() -> new ExamSystem().setVisible(true));
    }
}