document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("greet-form");
    const responseMessage = document.getElementById("response-message");

    form.addEventListener("submit", async (event) => {
        event.preventDefault(); // Prevent the form from refreshing the page
        const formData = new FormData(form);
        const name = formData.get("name");

        try {
            const response = await fetch("/api/greet", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({ name }),
            });

            if (response.ok) {
                const message = await response.json();
                responseMessage.textContent = message;
            } else {
                responseMessage.textContent = "Error: Unable to fetch greeting.";
            }
        } catch (error) {
            responseMessage.textContent = "Error: Something went wrong.";
        }
    });
});