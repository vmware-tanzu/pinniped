// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

window.onload = () => {
    Array.from(document.querySelectorAll('button')).forEach(btn => {
        btn.onclick = () => window.location.href = btn.dataset.url;
    });
    // Initially hidden to allow noscript tag to be the only visible content in the form in case Javascript is disabled.
    // Make it visible whenever Javascript is enabled.
    document.getElementById("choose-idp-form-buttons").hidden = false;
};
