import javax.swing.*;

public class ui {
    public static void main(String[] args) {
        JFrame frame = new JFrame("Suiren Encrypt");
        JButton b = new JButton("U want to encrypt what?");
        b.setBounds(100, 100, 200, 100);
        frame.add(b);
        frame.setLayout(null);
        frame.setVisible(true);
    }
}
