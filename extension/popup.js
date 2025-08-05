document.addEventListener("DOMContentLoaded", () => {
  const checkButton = document.getElementById("checkPhishing");
  const resultContainer = document.getElementById("result");
  const urlDisplay = document.getElementById("url-display");
  const statusDisplay = document.getElementById("status-display");
  const riskDisplay = document.getElementById("risk-display");
  const warningMessage = document.getElementById("warning-message");
  const safeMessage = document.getElementById("safe-message");

  // Click-to-scan behavior
  checkButton.addEventListener("click", () => {
    // Reset UI
    resultContainer.classList.remove("hidden");
    warningMessage.classList.add("hidden");
    safeMessage.classList.add("hidden");
    statusDisplay.textContent = "Scanning...";
    riskDisplay.textContent = "Analyzing...";

    // Get the active tab's URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      const url = activeTab.url;

      urlDisplay.textContent = url;

      chrome.runtime.sendMessage(
        { action: "checkPhishing", url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error("Runtime error:", chrome.runtime.lastError.message);
            statusDisplay.textContent = "Error: Could not determine.";
            return;
          }

          if (response.error) {
            statusDisplay.textContent = response.error;
            return;
          }

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

  // 🔁 Handle automatic feedback from background.js
  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "siteSafe") {
      resultContainer.classList.remove("hidden");
      warningMessage.classList.add("hidden");
      safeMessage.classList.remove("hidden");
      statusDisplay.textContent = "Safe Website";
      riskDisplay.textContent = "Low Risk";
    }
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "autoScanResult") {
      document.getElementById("result").classList.remove("hidden");

      document.getElementById("url-display").textContent = message.url;
      document.getElementById("status-display").textContent = message.isPhishing
        ? "Phishing Detected!"
        : "Safe Website";
      document.getElementById("risk-display").textContent = message.isPhishing
        ? "High Risk"
        : "Low Risk";

      if (message.isPhishing) {
        document.getElementById("warning-message").classList.remove("hidden");
        document.getElementById("safe-message").classList.add("hidden");
      } else {
        document.getElementById("safe-message").classList.remove("hidden");
        document.getElementById("warning-message").classList.add("hidden");
      }
    }
  });
});

// Save API Key to Chrome Storage
document.getElementById("saveApikey").addEventListener("click", () => {
  const apikey = document.getElementById("apikey-input").value.trim();
  if (apikey) {
    chrome.storage.local.set({ companyApiKey: apikey }, () => {
      document.getElementById("apikey-status").innerText = "API Key saved!";
      setTimeout(() => {
        document.getElementById("apikey-status").innerText = "";
      }, 2000);
    });
  }
});

// Load saved API Key into input on popup open
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["companyApiKey"], (result) => {
    if (result.companyApiKey) {
      document.getElementById("apikey-input").value = result.companyApiKey;
    }
  });
});
