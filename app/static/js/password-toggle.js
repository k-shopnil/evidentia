document.querySelectorAll(".password-toggle").forEach(function (btn) {
    btn.addEventListener("click", function () {
        var input = document.getElementById(btn.getAttribute("data-target"));
        if (!input) return;
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.setAttribute("aria-pressed", show ? "true" : "false");
        btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
        btn.classList.toggle("active", show);
        btn.querySelector(".icon-eye").classList.toggle("d-none", show);
        btn.querySelector(".icon-eye-off").classList.toggle("d-none", !show);
    });
});