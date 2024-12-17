chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        fetch("http://127.0.0.1:5000/classify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.phishing) {
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "red" });
                alert("Warning: This site is a phishing site!");
            } else {
                chrome.action.setBadgeText({ text: "" });
            }
        })
        .catch(error => console.error("Error:", error));
    }
});