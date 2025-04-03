document.addEventListener("DOMContentLoaded", () => {
  const checkButton = document.getElementById("checkPhishing");
  const resultContainer = document.getElementById("result");
  const urlDisplay = document.getElementById("url-display");
  const statusDisplay = document.getElementById("status-display");
  const riskDisplay = document.getElementById("risk-display");
  const warningMessage = document.getElementById("warning-message");
  const safeMessage = document.getElementById("safe-message");

  checkButton.addEventListener("click", () => {
    // Reset UI
    resultContainer.classList.remove("hidden");
    warningMessage.classList.add("hidden");
    safeMessage.classList.add("hidden");
    statusDisplay.textContent = "Scanning...";
    riskDisplay.textContent = "Analyzing...";

    // Get the URL of the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      const url = activeTab.url;

      urlDisplay.textContent = url; // Show the scanned URL

      console.log("Checking URL:", url);

      // Send the URL to the background script for analysis
      chrome.runtime.sendMessage(
        { action: "checkPhishing", url: url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error("Runtime error:", chrome.runtime.lastError.message);
            statusDisplay.textContent = "Error: Could not determine.";
            return;
          }

          if (response.error) {
            console.error("Response error:", response.error);
            statusDisplay.textContent = response.error;
            return;
          }

          // Update UI with results
          const isPhishing = response.isPhishing;
          statusDisplay.textContent = isPhishing
            ? "Phishing Detected!"
            : "Safe Website";
          riskDisplay.textContent = isPhishing ? "High Risk" : "Low Risk";

          if (isPhishing) {
            warningMessage.classList.remove("hidden");
          } else {
            safeMessage.classList.remove("hidden");
          }
        }
      );
    });
  });
});
