// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

window.onload = () => {
    const transitionToState = (id, message) => {
        // For the error state, there is also a message to show.
        if (id === 'error') {
            document.getElementById('message').innerText = message
        }

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
            mode: 'cors', // Using 'cors' is required to get actual response status codes.
            headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
            body: responseParams['encoded_params'].value,
        })
        .then(response => {
            clearTimeout(timeout);
            if (response.ok) {
                // Got 2XX http response status, so the user has logged in successfully.
                transitionToState('success');
            } else {
                // Got non-2XX http response status. Show the error after trying to read the response body.
                // These are not recoverable errors. The CLI stop listening and is no longer prompting for authcode.
                response.text()
                    .then(function (text) {
                        transitionToState('error', response.status + ": " + text);
                    })
                    .catch((reason) => {
                        console.error("error while reading response.text()", reason);
                        transitionToState('error', response.status + ": [could not read response body]");
                    })
            }
        })
        // A network error is encountered or CORS is misconfigured on the server-side.
        // This could happen in the case where the CLI is running on a different machine (e.g. ssh jumphost).
        // This always happens in Safari because that browser always prevents an https (TLS) web site from making
        // fetch calls to an http (non-TLS) localhost site (see https://bugs.webkit.org/show_bug.cgi?id=171934).
        .catch(() => transitionToState('manual'));
};
