package gov.dot.faa.ang.idms.acmetpm.wizard;

import java.io.IOException;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LayoutManager;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.LinearLayout.GrowPolicy;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

public class App {
    public static void main(String[] args) {
        var terminalFactory = new DefaultTerminalFactory();
        Screen screen = null; 

        try {
            screen = terminalFactory.createScreen();
            screen.startScreen();

            final var textGui = new MultiWindowTextGUI(screen);

            final var window = new BasicWindow("AcmeTPM Wizard");

            Panel contentPanel = new Panel(new GridLayout(2));

            GridLayout gridLayout = (GridLayout)contentPanel.getLayoutManager();
            gridLayout.setHorizontalSpacing(3);

            Label title = new Label("Acme TPM Configuration Window");
            title.setLayoutData(
                GridLayout.createLayoutData(
                    GridLayout.Alignment.BEGINNING, 
                    GridLayout.Alignment.BEGINNING,
                    true,   //grabExtraHorizontalSpace
                    true,//grabExtraVerticalSpace
                    2,//horizontalSpan
                    1 //verticalSpan
                )
            );


        } catch (IOException e) {
            // TODO: handle exception
        }

    }
}
