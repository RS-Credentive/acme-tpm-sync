package gov.dot.faa.ang.idms.acmetpm.wizard;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.TimeZone;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.ComboBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Separator;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

public class App {
    public static void main(String[] args) {
        var terminalFactory = new DefaultTerminalFactory();
        Screen screen = null; 

        try {
            screen = terminalFactory.createScreen();
            screen.startScreen();

            final var textGUI = new MultiWindowTextGUI(screen);

            final var window = new BasicWindow("AcmeTPM Wizard");

            Panel contentPanel = new Panel(new GridLayout(2));

            GridLayout gridLayout = (GridLayout)contentPanel.getLayoutManager();
            gridLayout.setHorizontalSpacing(3);

            Label title = new Label("Acme TPM Configuration Window");
            title.setLayoutData(
                GridLayout.createLayoutData(
                    GridLayout.Alignment.CENTER, 
                    GridLayout.Alignment.CENTER,
                    true,   //grabExtraHorizontalSpace
                    true,//grabExtraVerticalSpace
                    2,//horizontalSpan
                    1 //verticalSpan
                )
            );

            contentPanel.addComponent(new Label("Environment Variables"));
            contentPanel.addComponent(new Button("View...", new Runnable() {
                @Override
                public void run() {
                    MessageDialog.showMessageDialog(textGUI, "MessageBox", "This is a message box", MessageDialogButton.OK);
                }
            }).setLayoutData(GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER)));


            contentPanel.addComponent(new Label("Verifying Configuration..."));
            contentPanel.addComponent(
                new TextBox()
                .setLayoutData(
                    GridLayout.createLayoutData(
                        GridLayout.Alignment.BEGINNING, 
                        GridLayout.Alignment.CENTER
                    )
                )
            );

            

            contentPanel.addComponent(new Label("Password Box (right aligned)"));
            contentPanel.addComponent(
                new TextBox()
                .setMask('*')
                .setLayoutData(
                    GridLayout.createLayoutData(
                        GridLayout.Alignment.END, 
                        GridLayout.Alignment.CENTER
                    )
                )
            );

            contentPanel.addComponent(new Label("Read-only Combo Box (forced size)"));
            List<String> timezonesAsStrings = new ArrayList<String>();
            for(String id: TimeZone.getAvailableIDs()) {
                timezonesAsStrings.add(id);
            }
            ComboBox<String> readOnlyComboBox = new ComboBox<String>(timezonesAsStrings);
            readOnlyComboBox.setReadOnly(true);
            readOnlyComboBox.setPreferredSize(new TerminalSize(20, 1));
            contentPanel.addComponent(readOnlyComboBox);

            contentPanel.addComponent(new Label("Editable Combo Box (filled)"));
            contentPanel.addComponent(
                    new ComboBox<String>("Item #1", "Item #2", "Item #3", "Item #4")
                            .setReadOnly(false)
                            .setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1)));


            contentPanel.addComponent(new Label("Button (centered)"));
            contentPanel.addComponent(new Button("Button", new Runnable() {
                @Override
                public void run() {
                    MessageDialog.showMessageDialog(textGUI, "MessageBox", "This is a message box", MessageDialogButton.OK);
                }
            }).setLayoutData(GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER)));

            contentPanel.addComponent(
                new EmptySpace()
                .setLayoutData(
                        GridLayout.createHorizontallyFilledLayoutData(2)
                )
            );
            
            contentPanel.addComponent(
                new Separator(Direction.HORIZONTAL)
                .setLayoutData(
                        GridLayout.createHorizontallyFilledLayoutData(2)
                )
            );

            contentPanel.addComponent(
                new Button("Close", new Runnable() {
                    @Override
                    public void run() {
                        window.close();
                    }
                })
                .setLayoutData(
                    GridLayout.createHorizontallyEndAlignedLayoutData(2)
                )
            );

            window.setComponent(contentPanel);

            textGUI.addWindowAndWait(window);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(screen != null) {
                try {
                    screen.stopScreen();
                }
                catch(IOException e) {
                    e.printStackTrace();
                }
            }
        }


    }
}
