package emu.ui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.Tooltip;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class EmuSimulatorApp extends Application {

  private static final DateTimeFormatter REPORT_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

  private final ScenarioRunner runner = new ScenarioRunner();
  private final AdvancedOptionsPane advancedOptionsPane = new AdvancedOptionsPane();

  private final TextArea logArea = new TextArea();
  private final Label statusLabel = new Label("Ready");
  private final Button copyCliButton = new Button("Copy CLI");
  private final Label scenarioDescription = new Label("Select a scenario to see details.");

  private final Label verdictValue = valueLabel();
  private final Label smModeValue = valueLabel();
  private final Label paceValue = valueLabel();
  private final Label caValue = valueLabel();

  private final ListView<String> dgListView = new ListView<>();
  private final Label dg3ReadableValue = valueLabel();
  private final Label dg4ReadableValue = valueLabel();

  private Task<ScenarioResult> currentTask;
  private List<String> lastCommands = List.of();

  @Override
  public void start(Stage stage) {
    BorderPane root = new BorderPane();
    root.setLeft(buildScenarioPane());
    root.setCenter(buildResultTabs());
    root.setBottom(buildStatusBar());

    Scene scene = new Scene(root, 1280, 720);
    stage.setTitle("eMRTD Scenario Runner");
    stage.setScene(scene);
    stage.show();
  }

  @Override
  public void stop() {
    if (currentTask != null) {
      currentTask.cancel(true);
    }
  }

  private VBox buildScenarioPane() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(12));
    container.setPrefWidth(320);

    Label header = new Label("Scenario presets");
    header.getStyleClass().add("header-label");

    VBox buttonsBox = new VBox(8);
    for (ScenarioPreset preset : ScenarioPresets.all()) {
      Button button = new Button(preset.getName());
      button.setMaxWidth(Double.MAX_VALUE);
      button.setWrapText(true);
      button.setTooltip(new Tooltip(preset.getDescription()));
      button.setOnAction(e -> runScenario(preset));
      buttonsBox.getChildren().add(button);
    }

    ScrollPane scrollPane = new ScrollPane(buttonsBox);
    scrollPane.setFitToWidth(true);
    scrollPane.setPrefHeight(400);

    scenarioDescription.setWrapText(true);
    scenarioDescription.setPadding(new Insets(8, 0, 0, 0));

    container.getChildren().addAll(header, scrollPane, scenarioDescription, advancedOptionsPane);
    VBox.setVgrow(scrollPane, Priority.ALWAYS);

    return container;
  }

  private TabPane buildResultTabs() {
    TabPane tabs = new TabPane();
    tabs.getTabs().add(buildSummaryTab());
    tabs.getTabs().add(buildDataGroupsTab());
    tabs.getTabs().add(buildLogTab());
    tabs.getTabs().add(buildSecurityTab());
    return tabs;
  }

  private Tab buildSummaryTab() {
    GridPane grid = new GridPane();
    grid.setHgap(12);
    grid.setVgap(12);
    grid.setPadding(new Insets(16));

    addSummaryRow(grid, 0, "Passive Auth verdict", verdictValue);
    addSummaryRow(grid, 1, "Secure messaging", smModeValue);
    addSummaryRow(grid, 2, "PACE", paceValue);
    addSummaryRow(grid, 3, "Chip Authentication", caValue);

    Tab tab = new Tab("Summary", grid);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildDataGroupsTab() {
    VBox box = new VBox(8);
    box.setPadding(new Insets(16));

    Label presentLabel = new Label("Present Data Groups");
    dgListView.setPrefHeight(200);

    GridPane readabilityGrid = new GridPane();
    readabilityGrid.setHgap(12);
    readabilityGrid.setVgap(8);
    addSummaryRow(readabilityGrid, 0, "DG3 readable", dg3ReadableValue);
    addSummaryRow(readabilityGrid, 1, "DG4 readable", dg4ReadableValue);

    box.getChildren().addAll(presentLabel, dgListView, readabilityGrid);

    Tab tab = new Tab("Data Groups", box);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildLogTab() {
    logArea.setEditable(false);
    logArea.setWrapText(false);
    logArea.setStyle("-fx-font-family: 'Consolas', 'Monospaced';");

    Tab tab = new Tab("Technical Log", logArea);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildSecurityTab() {
    Label placeholder = new Label("Security explanations will surface here in a future milestone.");
    placeholder.setWrapText(true);
    placeholder.setPadding(new Insets(16));
    Tab tab = new Tab("Security Explained", placeholder);
    tab.setClosable(false);
    return tab;
  }

  private HBox buildStatusBar() {
    HBox bar = new HBox(12);
    bar.setPadding(new Insets(8, 12, 8, 12));
    bar.setAlignment(Pos.CENTER_LEFT);

    HBox.setHgrow(statusLabel, Priority.ALWAYS);
    statusLabel.setMaxWidth(Double.MAX_VALUE);

    copyCliButton.setDisable(true);
    copyCliButton.setOnAction(e -> copyLastCommands());

    bar.getChildren().addAll(statusLabel, copyCliButton);
    return bar;
  }

  private void runScenario(ScenarioPreset preset) {
    Objects.requireNonNull(preset, "preset");
    if (currentTask != null && currentTask.isRunning()) {
      currentTask.cancel(true);
    }

    scenarioDescription.setText(preset.getDescription());
    logArea.clear();
    clearSummary();
    clearDataGroups();
    statusLabel.setText("Running " + preset.getName() + "...");

    AdvancedOptionsSnapshot options = advancedOptionsPane.snapshot();
    Path reportPath = buildReportPath(preset.getName());

    currentTask = runner.createTask(preset, options, reportPath, this::appendLog);
    currentTask.setOnSucceeded(e -> handleCompletion(currentTask.getValue()));
    currentTask.setOnFailed(e -> handleFailure(preset.getName(), currentTask.getException()));
    currentTask.setOnCancelled(e -> statusLabel.setText("Cancelled"));

    Thread thread = new Thread(currentTask, "scenario-runner");
    thread.setDaemon(true);
    thread.start();
  }

  private void handleCompletion(ScenarioResult result) {
    lastCommands = result.getCommands();
    copyCliButton.setDisable(lastCommands.isEmpty());

    if (!result.isSuccess()) {
      String failureMsg = "Scenario failed";
      if (result.getFailedStep() != null) {
        failureMsg += " at " + result.getFailedStep();
      }
      failureMsg += " (exit code " + result.getExitCode() + ")";
      statusLabel.setText(failureMsg);
      return;
    }

    statusLabel.setText("Completed successfully");

    try {
      SessionReportViewData viewData = SessionReportParser.parse(result.getReportPath());
      if (viewData != null) {
        updateSummary(viewData);
        updateDataGroups(viewData);
      } else {
        statusLabel.setText("Completed (no report found)");
      }
    } catch (Exception ex) {
      statusLabel.setText("Completed (report parse error)");
      appendLog("[UI] Failed to parse report: " + ex.getMessage());
    }
  }

  private void handleFailure(String scenarioName, Throwable throwable) {
    lastCommands = List.of();
    copyCliButton.setDisable(true);
    statusLabel.setText("Error running " + scenarioName + "); see log.");
    appendLog("[UI] " + throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
  }

  private void appendLog(String message) {
    Platform.runLater(() -> {
      if (!logArea.getText().isEmpty()) {
        logArea.appendText(System.lineSeparator());
      }
      logArea.appendText(message);
    });
  }

  private void updateSummary(SessionReportViewData data) {
    verdictValue.setText(orDefault(data.getPassiveAuthVerdict()));
    String smMode = data.getSecureMessagingMode();
    if (smMode == null || smMode.isBlank()) {
      smModeValue.setText("—");
    } else {
      smModeValue.setText(smMode);
    }
    paceValue.setText(String.format("Attempted: %s | Established: %s",
        yesNo(data.isPaceAttempted()), yesNo(data.isPaceEstablished())));
    caValue.setText("Established: " + yesNo(data.isCaEstablished()));
  }

  private void updateDataGroups(SessionReportViewData data) {
    List<String> labels = new ArrayList<>();
    for (Integer dg : data.getPresentDataGroups()) {
      labels.add("DG" + dg);
    }
    dgListView.getItems().setAll(labels);
    dg3ReadableValue.setText(yesNo(data.isDg3Readable()));
    dg4ReadableValue.setText(yesNo(data.isDg4Readable()));
  }

  private void clearSummary() {
    verdictValue.setText("—");
    smModeValue.setText("—");
    paceValue.setText("—");
    caValue.setText("—");
  }

  private void clearDataGroups() {
    dgListView.getItems().clear();
    dg3ReadableValue.setText("—");
    dg4ReadableValue.setText("—");
  }

  private void copyLastCommands() {
    if (lastCommands.isEmpty()) {
      return;
    }
    ClipboardContent content = new ClipboardContent();
    content.putString(String.join(System.lineSeparator(), lastCommands));
    Clipboard.getSystemClipboard().setContent(content);
    statusLabel.setText("CLI copied to clipboard");
  }

  private Path buildReportPath(String scenarioName) {
    String safeName = scenarioName.toLowerCase()
        .replaceAll("[^a-z0-9]+", "-")
        .replaceAll("-+", "-")
        .replaceAll("^-|-$", "");
    String fileName = safeName + "-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + ".json";
    return Paths.get("target", "ui-session", fileName);
  }

  private static void addSummaryRow(GridPane grid, int row, String labelText, Label value) {
    Label label = new Label(labelText);
    GridPane.setRowIndex(label, row);
    GridPane.setColumnIndex(label, 0);
    GridPane.setRowIndex(value, row);
    GridPane.setColumnIndex(value, 1);
    grid.getChildren().addAll(label, value);
  }

  private static Label valueLabel() {
    Label label = new Label("—");
    label.getStyleClass().add("value-label");
    return label;
  }

  private static String yesNo(boolean value) {
    return value ? "Yes" : "No";
  }

  private static String orDefault(String value) {
    return (value == null || value.isBlank()) ? "—" : value;
  }

  public static void main(String[] args) {
    launch(args);
  }
}

