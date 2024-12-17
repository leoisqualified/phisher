chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    fetch("http://127.0.0.1:5000/classify", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        const resultElement = document.getElementById("result");
        if (data.phishing) {
            resultElement.textContent = "This is a phishing site!";
            resultElement.style.color = "red";
        } else {
            resultElement.textContent = "This site is safe.";
            resultElement.style.color = "green";
        }
    })
    .catch(error => {
        const resultElement = document.getElementById("result");
        resultElement.textContent = "Error analyzing the site.";
        resultElement.style.color = "orange";
        console.error("Error:", error);
    });
});
