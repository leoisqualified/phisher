chrome.runtime.sendMessage(
  { action: "checkPhishing", url: window.location.href },
  (response) => {
    if (chrome.runtime.lastError) {
      console.error("Runtime error:", chrome.runtime.lastError.message);
      resultContainer.textContent = "Error: Could not determine.";
    } else if (response.error) {
      console.error("Response error:", response.error);
      resultContainer.textContent = response.error;
    } else {
      resultContainer.textContent = response.isPhishing
        ? "This site is a phishing website."
        : "This site is safe.";
    }
  }
);
