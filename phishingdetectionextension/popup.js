document.getElementById("checkPhishing").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, { action: "checkPhishing" }, (response) => {
        const resultDiv = document.getElementById("result");
        if (response && response.prediction) {
          if (response.prediction === "Phishing") {
            resultDiv.textContent = "⚠️ Warning: This site is phishing!";
            resultDiv.style.color = "red";
          } else {
            resultDiv.textContent = "✅ This site is safe.";
            resultDiv.style.color = "green";
          }
        } else {
          resultDiv.textContent = "Error: Could not determine.";
          resultDiv.style.color = "gray";
        }
      });
    });
  });
  