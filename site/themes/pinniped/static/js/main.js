"use strict";

function mobileNavToggle() {
    var menu = document.getElementById("mobile-menu").parentElement;
    menu.classList.toggle('mobile-menu-visible');
}
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('mobile-menu-button').addEventListener('click', mobileNavToggle);
});