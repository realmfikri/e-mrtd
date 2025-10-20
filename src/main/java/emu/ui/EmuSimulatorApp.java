package emu.ui;

import emu.SessionReport;
import emu.SimLogCategory;
import emu.SimPhase;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import javafx.util.Callback;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Objects;

public final class EmuSimulatorApp extends Application {

  private static final DateTimeFormatter REPORT_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

  private final ScenarioRunner runner = new ScenarioRunner();
  private final AdvancedOptionsPane advancedOptionsPane = new AdvancedOptionsPane();

  private Stage primaryStage;

  private final ObservableList<LogEntry> logEntries = FXCollections.observableArrayList();
  private final FilteredList<LogEntry> filteredLogs = new FilteredList<>(logEntries);
  private final ListView<LogEntry> logListView = new ListView<>(filteredLogs);
  private final ToggleGroup logFilterGroup = new ToggleGroup();
  private final Label statusLabel = new Label("Ready");
  private final Button copyCliButton = new Button("Copy CLI");
  private final Button copySessionInfoButton = new Button("Copy session info");
  private final Button exportButton = new Button("Export session");
  private final Button runDoc9303Button = new Button("Run ICAO Doc 9303 flow");
  private final Button runAllButton = new Button("Run all tests");
  private final Label scenarioDescription = new Label("Select a scenario to see details.");

  private final Label verdictValue = valueLabel();
  private final Label smModeValue = valueLabel();
  private final Label paceValue = valueLabel();
  private final Label caValue = valueLabel();

  private final ListView<String> dgListView = new ListView<>();
  private final Label dg3ReadableValue = valueLabel();
  private final Label dg4ReadableValue = valueLabel();
  private final EnumMap<SimPhase, Label> phaseLabels = new EnumMap<>(SimPhase.class);
  private final Label securityContent = new Label("Security explanations will surface here in a future milestone.");
  private final List<SimPhase> phaseOrder = List.of(
      SimPhase.CONNECTING,
      SimPhase.AUTHENTICATING,
      SimPhase.READING,
      SimPhase.VERIFYING,
      SimPhase.COMPLETE);

  private static final int MAX_LOG_ENTRIES = 2000;

  private Task<ScenarioResult> currentTask;
  private List<String> lastCommands = List.of();
  private SessionReport lastReport;
  private SimPhase currentPhase = SimPhase.CONNECTING;
  private Path lastReportPath;
  private ScenarioResult lastScenarioResult;
  private Throwable lastScenarioException;
  private Runnable afterScenarioCallback;
  private BatchRunState batchRunState;
  private VBox scenarioButtonsBox;

  @Override
  public void start(Stage stage) {
    this.primaryStage = stage;
    BorderPane root = new BorderPane();
    root.setLeft(buildScenarioPane());
    root.setCenter(buildResultPane());
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

    scenarioButtonsBox = new VBox(8);
    for (ScenarioPreset preset : ScenarioPresets.all()) {
      Button button = new Button(preset.getName());
      button.setMaxWidth(Double.MAX_VALUE);
      button.setWrapText(true);
      button.setTooltip(new Tooltip(preset.getDescription()));
      button.setOnAction(e -> runScenario(preset));
      scenarioButtonsBox.getChildren().add(button);
    }

    ScenarioPreset icaoPreset = ScenarioPresets.icaoDoc9303();
    runDoc9303Button.setMaxWidth(Double.MAX_VALUE);
    runDoc9303Button.setWrapText(true);
    runDoc9303Button.setTooltip(new Tooltip(icaoPreset.getDescription()));
    runDoc9303Button.setOnAction(e -> runScenario(icaoPreset));

    runAllButton.setMaxWidth(Double.MAX_VALUE);
    runAllButton.setOnAction(e -> runAllScenarios());

    ScrollPane scrollPane = new ScrollPane(scenarioButtonsBox);
    scrollPane.setFitToWidth(true);
    scrollPane.setPrefHeight(400);

    scenarioDescription.setWrapText(true);
    scenarioDescription.setPadding(new Insets(8, 0, 0, 0));

    container.getChildren().addAll(header, runDoc9303Button, runAllButton, scrollPane, scenarioDescription, advancedOptionsPane);
    VBox.setVgrow(scrollPane, Priority.ALWAYS);

    return container;
  }

  private VBox buildResultPane() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(12));
    HBox stepper = buildStepper();
    TabPane tabs = buildResultTabs();
    container.getChildren().addAll(stepper, tabs);
    VBox.setVgrow(tabs, Priority.ALWAYS);
    return container;
  }

  private HBox buildStepper() {
    HBox stepper = new HBox(16);
    stepper.setAlignment(Pos.CENTER_LEFT);
    for (SimPhase phase : phaseOrder) {
      Label label = new Label(formatPhaseLabel(phase, "○"));
      label.getStyleClass().add("stepper-label");
      phaseLabels.put(phase, label);
      stepper.getChildren().add(label);
    }
    return stepper;
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
    HBox filters = new HBox(8);
    filters.setAlignment(Pos.CENTER_LEFT);
    RadioButton allButton = new RadioButton("All");
    allButton.setToggleGroup(logFilterGroup);
    allButton.setUserData(null);
    allButton.setSelected(true);
    RadioButton apduButton = new RadioButton("APDU");
    apduButton.setToggleGroup(logFilterGroup);
    apduButton.setUserData(SimLogCategory.APDU);
    RadioButton securityButton = new RadioButton("Security");
    securityButton.setToggleGroup(logFilterGroup);
    securityButton.setUserData(SimLogCategory.SECURITY);
    filters.getChildren().addAll(new Label("Filter:"), allButton, apduButton, securityButton);

    logListView.setCellFactory(createLogCellFactory());
    logListView.setPlaceholder(new Label("Logs will appear here during execution."));

    VBox container = new VBox(8, filters, logListView);
    VBox.setVgrow(logListView, Priority.ALWAYS);

    logFilterGroup.selectedToggleProperty().addListener((obs, oldToggle, newToggle) -> {
      if (newToggle == null) {
        filteredLogs.setPredicate(log -> true);
      } else {
        SimLogCategory category = (SimLogCategory) newToggle.getUserData();
        if (category == null) {
          filteredLogs.setPredicate(log -> true);
        } else {
          filteredLogs.setPredicate(log -> log.getCategory() == category);
        }
      }
    });

    Tab tab = new Tab("Technical Log", container);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildSecurityTab() {
    securityContent.setWrapText(true);
    securityContent.setPadding(new Insets(16));
    Tab tab = new Tab("Security Explained", securityContent);
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
    copySessionInfoButton.setDisable(true);
    copySessionInfoButton.setOnAction(e -> copySessionInfo());
    exportButton.setDisable(true);
    exportButton.setOnAction(e -> exportSession());

    bar.getChildren().addAll(statusLabel, copyCliButton, copySessionInfoButton, exportButton);
    return bar;
  }

  private void runScenario(ScenarioPreset preset) {
    startScenario(preset, advancedOptionsPane.snapshot(), null);
  }

  private void startScenario(
      ScenarioPreset preset,
      AdvancedOptionsSnapshot options,
      Runnable completionCallback) {
    Objects.requireNonNull(preset, "preset");
    Objects.requireNonNull(options, "options");

    if (currentTask != null && currentTask.isRunning()) {
      statusLabel.setText("A scenario is already running; please wait");
      return;
    }

    afterScenarioCallback = completionCallback;
    lastScenarioResult = null;
    lastScenarioException = null;

    scenarioDescription.setText(preset.getDescription());
    logEntries.clear();
    if (!logFilterGroup.getToggles().isEmpty()) {
      logFilterGroup.selectToggle(logFilterGroup.getToggles().get(0));
    }
    clearSummary();
    clearDataGroups();
    resetStepper();
    lastReport = null;
    lastReportPath = null;
    copyCliButton.setDisable(true);
    copySessionInfoButton.setDisable(true);
    exportButton.setDisable(true);
    runDoc9303Button.setDisable(true);
    runAllButton.setDisable(true);
    statusLabel.setText("Running " + preset.getName() + "...");

    Path reportPath = buildReportPath(preset.getName());

    UiScenarioListener listener = new UiScenarioListener();
    currentTask = runner.createTask(preset, options, reportPath, listener);
    currentTask.setOnSucceeded(e -> handleCompletion(currentTask.getValue()));
    currentTask.setOnFailed(e -> handleFailure(preset.getName(), currentTask.getException()));
    currentTask.setOnCancelled(e -> {
      statusLabel.setText("Cancelled");
      finishScenario();
    });

    Thread thread = new Thread(currentTask, "scenario-runner");
    thread.setDaemon(true);
    thread.start();
  }

  private void runAllScenarios() {
    if (batchRunState != null) {
      statusLabel.setText("Already running all tests");
      return;
    }
    if (currentTask != null && currentTask.isRunning()) {
      statusLabel.setText("Finish current scenario before running all tests");
      return;
    }

    List<ScenarioPreset> presets = new ArrayList<>(ScenarioPresets.all());
    if (presets.isEmpty()) {
      statusLabel.setText("No scenarios available to run");
      return;
    }

    AdvancedOptionsSnapshot options = advancedOptionsPane.snapshot();
    batchRunState = new BatchRunState(presets, options);
    if (scenarioButtonsBox != null) {
      scenarioButtonsBox.setDisable(true);
    }
    runDoc9303Button.setDisable(true);
    runAllButton.setDisable(true);
    statusLabel.setText("Running all tests...");
    runNextScenarioInBatch();
  }

  private void runNextScenarioInBatch() {
    if (batchRunState == null) {
      return;
    }
    if (batchRunState.index >= batchRunState.presets.size()) {
      finishBatchRun();
      return;
    }

    ScenarioPreset preset = batchRunState.presets.get(batchRunState.index);
    startScenario(preset, batchRunState.options, () -> {
      String summary = buildBatchSummary(preset);
      batchRunState.summaries.add(summary);
      batchRunState.index++;
      runNextScenarioInBatch();
    });
  }

  private void finishBatchRun() {
    if (batchRunState == null) {
      return;
    }
    boolean clipboardSuccess = false;
    Path summaryPath = null;
    if (!batchRunState.summaries.isEmpty()) {
      String joinedSummaries = joinBatchSummaries(batchRunState.summaries);
      clipboardSuccess = copyBatchSummariesToClipboard(joinedSummaries);
      summaryPath = writeBatchSummariesToFile(joinedSummaries);
    }
    if (scenarioButtonsBox != null) {
      scenarioButtonsBox.setDisable(false);
    }
    runAllButton.setDisable(false);
    runDoc9303Button.setDisable(false);
    if (summaryPath != null) {
      String message = clipboardSuccess
          ? "Completed all tests; summary copied to clipboard and saved to " + summaryPath
          : "Completed all tests; summary saved to " + summaryPath;
      statusLabel.setText(message);
    } else if (clipboardSuccess) {
      statusLabel.setText("Completed all tests; summary copied to clipboard");
    } else {
      statusLabel.setText("Completed all tests");
    }
    addLogEntry(SimLogCategory.GENERAL, "UI", "All scenario tests finished");
    batchRunState = null;
  }

  private String buildBatchSummary(ScenarioPreset preset) {
    String newline = System.lineSeparator();
    StringBuilder sb = new StringBuilder();
    sb.append("Scenario: ").append(preset.getName()).append(newline);
    sb.append("Explanation: ").append(preset.getDescription()).append(newline);

    if (lastScenarioResult != null) {
      if (lastScenarioResult.isSuccess()) {
        sb.append("Outcome: Success").append(newline);
        sb.append(buildSessionInfoText("  ")).append(newline);
      } else {
        sb.append("Outcome: Failed");
        if (lastScenarioResult.getFailedStep() != null) {
          sb.append(" at ").append(lastScenarioResult.getFailedStep());
        }
        sb.append(" (exit code ").append(lastScenarioResult.getExitCode()).append(")").append(newline);
        if (!lastScenarioResult.getCommands().isEmpty()) {
          sb.append("  Commands executed:").append(newline);
          for (String cmd : lastScenarioResult.getCommands()) {
            sb.append("    $").append(' ').append(cmd).append(newline);
          }
        }
        sb.append(buildSessionInfoText("  ")).append(newline);
      }
    } else if (lastScenarioException != null) {
      sb.append("Outcome: Error - ")
          .append(lastScenarioException.getClass().getSimpleName())
          .append(": ")
          .append(lastScenarioException.getMessage())
          .append(newline);
      sb.append(buildSessionInfoText("  ")).append(newline);
    } else {
      sb.append("Outcome: Cancelled").append(newline);
      sb.append(buildSessionInfoText("  ")).append(newline);
    }

    return sb.toString().stripTrailing();
  }

  private String joinBatchSummaries(List<String> summaries) {
    String newline = System.lineSeparator();
    return String.join(newline + newline, summaries);
  }

  private boolean copyBatchSummariesToClipboard(String joined) {
    try {
      ClipboardContent content = new ClipboardContent();
      content.putString(joined);
      Clipboard.getSystemClipboard().setContent(content);
      return true;
    } catch (RuntimeException ex) {
      addLogEntry(
          SimLogCategory.GENERAL,
          "UI",
          "Unable to copy batch summary to clipboard: " + ex.getMessage());
      return false;
    }
  }

  private Path writeBatchSummariesToFile(String joined) {
    Path directory = Paths.get("target", "ui-session");
    try {
      Files.createDirectories(directory);
      String fileName = "batch-summary-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + ".txt";
      Path destination = directory.resolve(fileName);
      Files.writeString(
          destination,
          joined,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
      return destination;
    } catch (IOException ex) {
      addLogEntry(
          SimLogCategory.GENERAL,
          "UI",
          "Unable to write batch summary to file: " + ex.getMessage());
      return null;
    }
  }

  private void handleCompletion(ScenarioResult result) {
    lastScenarioResult = result;
    lastScenarioException = null;

    lastCommands = result.getCommands();
    copyCliButton.setDisable(lastCommands.isEmpty());
    lastReportPath = result.getReportPath();

    if (!result.isSuccess()) {
      String failureMsg = "Scenario failed";
      if (result.getFailedStep() != null) {
        failureMsg += " at " + result.getFailedStep();
      }
      failureMsg += " (exit code " + result.getExitCode() + ")";
      statusLabel.setText(failureMsg);
      exportButton.setDisable(true);
      copySessionInfoButton.setDisable(false);
      finishScenario();
      return;
    }

    statusLabel.setText("Completed successfully");

    SessionReport report = result.getReport();
    if (report == null) {
      report = lastReport;
    }
    if (report != null) {
      SessionReportViewData viewData = SessionReportParser.fromReport(report);
      if (viewData != null) {
        updateSummary(viewData);
        updateDataGroups(viewData);
      }
      lastReport = report;
      exportButton.setDisable(false);
      copySessionInfoButton.setDisable(false);
    } else {
      try {
        SessionReportViewData viewData = SessionReportParser.parse(result.getReportPath());
        if (viewData != null) {
          updateSummary(viewData);
          updateDataGroups(viewData);
          exportButton.setDisable(false);
          copySessionInfoButton.setDisable(false);
        } else {
          statusLabel.setText("Completed (no report found)");
          exportButton.setDisable(true);
          copySessionInfoButton.setDisable(false);
        }
      } catch (Exception ex) {
        statusLabel.setText("Completed (report parse error)");
        addLogEntry(SimLogCategory.GENERAL, "UI", "Failed to parse report: " + ex.getMessage());
        exportButton.setDisable(true);
        copySessionInfoButton.setDisable(false);
      }
    }

    finishScenario();
  }

  private void handleFailure(String scenarioName, Throwable throwable) {
    lastScenarioResult = null;
    lastScenarioException = throwable;

    lastCommands = List.of();
    copyCliButton.setDisable(true);
    exportButton.setDisable(true);
    statusLabel.setText("Error running " + scenarioName + "); see log.");
    addLogEntry(SimLogCategory.GENERAL, "UI", throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
    copySessionInfoButton.setDisable(false);
    finishScenario();
  }

  private void finishScenario() {
    currentTask = null;

    Runnable callback = afterScenarioCallback;
    afterScenarioCallback = null;
    if (callback != null) {
      callback.run();
    }

    if (batchRunState == null) {
      runAllButton.setDisable(false);
      runDoc9303Button.setDisable(false);
      if (scenarioButtonsBox != null) {
        scenarioButtonsBox.setDisable(false);
      }
    }
  }

  private Callback<ListView<LogEntry>, ListCell<LogEntry>> createLogCellFactory() {
    return list -> new ListCell<>() {
      @Override
      protected void updateItem(LogEntry entry, boolean empty) {
        super.updateItem(entry, empty);
        if (empty || entry == null) {
          setText(null);
        } else {
          setText(formatLogEntry(entry));
        }
      }
    };
  }

  private void addLogEntry(SimLogCategory category, String source, String message) {
    LogEntry entry = new LogEntry(category, source, message);
    logEntries.add(entry);
    if (logEntries.size() > MAX_LOG_ENTRIES) {
      logEntries.remove(0);
    }
    if (!logEntries.isEmpty()) {
      logListView.scrollTo(logEntries.size() - 1);
    }
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

  private void resetStepper() {
    for (SimPhase phase : phaseOrder) {
      Label label = phaseLabels.get(phase);
      if (label != null) {
        label.setText(formatPhaseLabel(phase, "○"));
      }
    }
    currentPhase = SimPhase.CONNECTING;
  }

  private void updatePhaseIndicator(SimPhase phase, String detail) {
    if (phase == SimPhase.FAILED) {
      Label label = phaseLabels.get(currentPhase);
      if (label != null) {
        label.setText(formatPhaseLabel(currentPhase, "✕"));
      }
      if (detail != null && !detail.isBlank()) {
        statusLabel.setText(detail);
      }
      return;
    }

    int phaseIndex = phaseOrder.indexOf(phase);
    if (phaseIndex < 0) {
      return;
    }

    currentPhase = phase;
    for (int i = 0; i < phaseOrder.size(); i++) {
      SimPhase iter = phaseOrder.get(i);
      Label label = phaseLabels.get(iter);
      if (label == null) {
        continue;
      }
      if (i < phaseIndex) {
        label.setText(formatPhaseLabel(iter, "✓"));
      } else if (i == phaseIndex) {
        label.setText(formatPhaseLabel(iter, phase == SimPhase.COMPLETE ? "✓" : "●"));
      } else {
        label.setText(formatPhaseLabel(iter, "○"));
      }
    }

    if (detail != null && !detail.isBlank()) {
      statusLabel.setText(detail);
    }
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

  private void copySessionInfo() {
    String summary = buildSessionInfoText("");
    ClipboardContent content = new ClipboardContent();
    content.putString(summary);
    Clipboard.getSystemClipboard().setContent(content);
    statusLabel.setText("Session info copied to clipboard");
  }

  private String buildSessionInfoText(String indent) {
    String newline = System.lineSeparator();
    String baseIndent = indent == null ? "" : indent;
    String levelOne = baseIndent + "  ";

    StringBuilder sb = new StringBuilder();

    sb.append(baseIndent).append("Summary").append(newline);
    sb.append(levelOne).append("Passive Auth verdict: ").append(verdictValue.getText()).append(newline);
    sb.append(levelOne).append("Secure messaging: ").append(smModeValue.getText()).append(newline);
    sb.append(levelOne).append("PACE: ").append(paceValue.getText()).append(newline);
    sb.append(levelOne).append("Chip Authentication: ").append(caValue.getText()).append(newline).append(newline);

    sb.append(baseIndent).append("Data Groups").append(newline);
    if (dgListView.getItems().isEmpty()) {
      sb.append(levelOne).append("(none)").append(newline);
    } else {
      for (String dg : dgListView.getItems()) {
        sb.append(levelOne).append(dg).append(newline);
      }
    }
    sb.append(levelOne).append("DG3 readable: ").append(dg3ReadableValue.getText()).append(newline);
    sb.append(levelOne).append("DG4 readable: ").append(dg4ReadableValue.getText()).append(newline).append(newline);

    sb.append(baseIndent).append("Technical Log").append(newline);
    if (logEntries.isEmpty()) {
      sb.append(levelOne).append("(no entries)").append(newline);
    } else {
      for (LogEntry entry : logEntries) {
        sb.append(levelOne).append(formatLogEntry(entry)).append(newline);
      }
    }
    sb.append(newline);

    sb.append(baseIndent).append("Security Explained").append(newline);
    String securityText = securityContent.getText();
    if (securityText == null || securityText.isBlank()) {
      sb.append(levelOne).append("(no details available)").append(newline);
    } else {
      for (String line : securityText.split("\r?\n")) {
        sb.append(levelOne).append(line).append(newline);
      }
    }

    return sb.toString();
  }

  private Path buildReportPath(String scenarioName) {
    String safeName = scenarioName.toLowerCase()
        .replaceAll("[^a-z0-9]+", "-")
        .replaceAll("-+", "-")
        .replaceAll("^-|-$", "");
    String fileName = safeName + "-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + ".json";
    return Paths.get("target", "ui-session", fileName);
  }

  private void exportSession() {
    if (lastReport == null && (lastReportPath == null || !Files.exists(lastReportPath))) {
      statusLabel.setText("No session to export yet");
      return;
    }

    DirectoryChooser chooser = new DirectoryChooser();
    chooser.setTitle("Export session");
    File chosen = chooser.showDialog(primaryStage);
    if (chosen == null) {
      return;
    }

    Path targetDir = chosen.toPath();
    String timestamp = REPORT_TIMESTAMP.format(LocalDateTime.now());
    Path jsonPath = targetDir.resolve("session-report-" + timestamp + ".json");
    Path logPath = targetDir.resolve("session-log-" + timestamp + ".txt");
    Path cliPath = targetDir.resolve("session-cli-" + timestamp + ".txt");

    try {
      Files.createDirectories(targetDir);
      if (lastReport != null) {
        lastReport.write(jsonPath);
      } else if (lastReportPath != null && Files.exists(lastReportPath)) {
        Files.copy(lastReportPath, jsonPath, StandardCopyOption.REPLACE_EXISTING);
      }

      StringBuilder logBuilder = new StringBuilder();
      for (LogEntry entry : logEntries) {
        logBuilder.append(formatLogEntry(entry)).append(System.lineSeparator());
      }
      Files.writeString(logPath, logBuilder.toString(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

      if (!lastCommands.isEmpty()) {
        Files.writeString(
            cliPath,
            String.join(System.lineSeparator(), lastCommands),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
      }

      statusLabel.setText("Exported session to " + targetDir.toAbsolutePath());
      addLogEntry(SimLogCategory.GENERAL, "UI", "Session exported to " + targetDir.toAbsolutePath());
    } catch (IOException e) {
      statusLabel.setText("Failed to export session");
      addLogEntry(SimLogCategory.GENERAL, "UI", "Export failed: " + e.getMessage());
    }
  }

  private static String formatPhaseLabel(SimPhase phase, String indicator) {
    return indicator + " " + phaseDisplayName(phase);
  }

  private static String phaseDisplayName(SimPhase phase) {
    String name = phase.name().toLowerCase().replace('_', ' ');
    return Character.toUpperCase(name.charAt(0)) + name.substring(1);
  }

  private String formatLogEntry(LogEntry entry) {
    StringBuilder sb = new StringBuilder();
    sb.append('[').append(entry.getCategory().name()).append(']');
    if (entry.getSource() != null && !entry.getSource().isBlank()) {
      sb.append(' ').append('[').append(entry.getSource()).append(']');
    }
    sb.append(' ').append(entry.getMessage());
    return sb.toString();
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

  private static final class BatchRunState {
    final List<ScenarioPreset> presets;
    final AdvancedOptionsSnapshot options;
    final List<String> summaries = new ArrayList<>();
    int index;

    BatchRunState(List<ScenarioPreset> presets, AdvancedOptionsSnapshot options) {
      this.presets = List.copyOf(presets);
      this.options = options;
      this.index = 0;
    }
  }

  private final class UiScenarioListener implements ScenarioExecutionListener {
    @Override
    public void onLog(SimLogCategory category, String source, String message) {
      Platform.runLater(() -> addLogEntry(category, source, message));
    }

    @Override
    public void onPhase(SimPhase phase, String detail) {
      Platform.runLater(() -> updatePhaseIndicator(phase, detail));
    }

    @Override
    public void onReport(SessionReport report) {
      Platform.runLater(() -> lastReport = report);
    }
  }

  public static void main(String[] args) {
    launch(args);
  }
}

