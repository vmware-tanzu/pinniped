// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

window.onload = () => {
    const transitionToState = (id) => {
        // Hide all the other ".state" <div>s.
        Array.from(document.querySelectorAll('.state')).forEach(e => e.hidden = true);

        // Unhide the current state <div>.
        const currentDiv = document.getElementById(id)
        currentDiv.hidden = false;

        // Set the window title.
        document.title = currentDiv.dataset.title;

        // Set the favicon using inline SVG (does not work on Safari).
        document.getElementById('favicon').setAttribute(
            'href',
            'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>' +
            currentDiv.dataset.favicon +
            '</text></svg>'
        );
    }

    // At load, show the spinner, hide the other divs, set the favicon, and
    // replace the URL path with './' so the upstream auth code disappears.
    transitionToState('loading');
    window.history.replaceState(null, '', './');

    // When the copy button is clicked, copy to the clipboard.
    document.getElementById('manual-copy-button').onclick = () => {
        const code = document.getElementById('manual-copy-button').innerText;
        navigator.clipboard.writeText(code)
            .then(() => console.info('copied authorization code ' + code + ' to clipboard'))
            .catch(e => console.error('failed to copy code ' + code + ' to clipboard: ' + e));
    };

    // Set a timeout to transition to the "manual" state if nothing succeeds within 2s.
    const timeout = setTimeout(() => transitionToState('manual'), 2000);

    // Try to submit the POST callback, handling the success and error cases.
    const responseParams = document.forms[0].elements;
    fetch(
        responseParams['redirect_uri'].value,
        {
            method: 'POST',
            mode: 'no-cors',
            headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
            body: responseParams['encoded_params'].value,
        })
        .then(() => clearTimeout(timeout))
        .then(() => transitionToState('success'))
        .catch(() => transitionToState('manual'));
};
